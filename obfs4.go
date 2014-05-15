/*
 * Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Package obfs4 implements the obfs4 protocol.
package obfs4

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/yawning/obfs4/framing"
	"github.com/yawning/obfs4/ntor"
)

const (
	headerLength      = framing.FrameOverhead + packetOverhead
	connectionTimeout = time.Duration(15) * time.Second

	minCloseThreshold = 0
	maxCloseThreshold = framing.MaximumSegmentLength * 5
	minCloseInterval  = 0
	maxCloseInterval  = 60
)

type connState int

const (
	stateInit connState = iota
	stateEstablished
	stateBroken
	stateClosed
)

// Obfs4Conn is the implementation of the net.Conn interface for obfs4
// connections.
type Obfs4Conn struct {
	conn net.Conn

	lenProbDist *wDist

	encoder *framing.Encoder
	decoder *framing.Decoder

	receiveBuffer        bytes.Buffer
	receiveDecodedBuffer bytes.Buffer

	state    connState
	isServer bool

	// Server side state.
	listener *Obfs4Listener
}

func (c *Obfs4Conn) padBurst(burst *bytes.Buffer) (err error) {
	tailLen := burst.Len() % framing.MaximumSegmentLength
	toPadTo := c.lenProbDist.sample()

	padLen := 0
	if toPadTo >= tailLen {
		padLen = toPadTo - tailLen
	} else {
		padLen = (framing.MaximumSegmentLength - tailLen) + toPadTo
	}

	if padLen > headerLength {
		err = c.producePacket(burst, packetTypePayload, []byte{},
			uint16(padLen-headerLength))
		if err != nil {
			return
		}
	} else if padLen > 0 {
		err = c.producePacket(burst, packetTypePayload, []byte{},
			maxPacketPayloadLength)
		if err != nil {
			return
		}
		err = c.producePacket(burst, packetTypePayload, []byte{},
			uint16(padLen))
		if err != nil {
			return
		}
	}

	return
}

func (c *Obfs4Conn) closeAfterDelay() {
	// I-it's not like I w-wanna handshake with you or anything.  B-b-baka!
	defer c.conn.Close()

	delaySecs := randRange(minCloseInterval, maxCloseInterval)
	toDiscard := randRange(minCloseThreshold, maxCloseThreshold)

	delay := time.Duration(delaySecs) * time.Second
	err := c.conn.SetReadDeadline(time.Now().Add(delay))
	if err != nil {
		return
	}

	// Consume and discard data on this connection until either the specified
	// interval passes or a certain size has been reached.
	discarded := 0
	var buf [framing.MaximumSegmentLength]byte
	for discarded < int(toDiscard) {
		n, err := c.conn.Read(buf[:])
		if err != nil {
			return
		}
		discarded += n
	}
}

func (c *Obfs4Conn) setBroken() {
	c.state = stateBroken
}

func (c *Obfs4Conn) clientHandshake(nodeID *ntor.NodeID, publicKey *ntor.PublicKey) (err error) {
	if c.isServer {
		panic(fmt.Sprintf("BUG: clientHandshake() called for server connection"))
	}

	defer func() {
		if err != nil {
			c.setBroken()
		}
	}()

	// Generate/send the client handshake.
	var hs *clientHandshake
	var blob []byte
	hs, err = newClientHandshake(nodeID, publicKey)
	if err != nil {
		return
	}
	blob, err = hs.generateHandshake()
	if err != nil {
		return
	}

	err = c.conn.SetDeadline(time.Now().Add(connectionTimeout * 2))
	if err != nil {
		return
	}

	_, err = c.conn.Write(blob)
	if err != nil {
		return
	}

	// Consume the server handshake.
	var hsBuf [serverMaxHandshakeLength]byte
	for {
		var n int
		n, err = c.conn.Read(hsBuf[:])
		if err != nil {
			// Yes, just bail out of handshaking even if the Read could have
			// returned data, no point in continuing on EOF/etc.
			return
		}
		c.receiveBuffer.Write(hsBuf[:n])

		var seed []byte
		n, seed, err = hs.parseServerHandshake(c.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return
		}
		_ = c.receiveBuffer.Next(n)

		err = c.conn.SetDeadline(time.Time{})
		if err != nil {
			return
		}

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		c.encoder = framing.NewEncoder(okm[:framing.KeyLength])
		c.decoder = framing.NewDecoder(okm[framing.KeyLength:])

		c.state = stateEstablished

		return nil
	}
}

func (c *Obfs4Conn) serverHandshake(nodeID *ntor.NodeID, keypair *ntor.Keypair) (err error) {
	if !c.isServer {
		panic(fmt.Sprintf("BUG: serverHandshake() called for client connection"))
	}

	defer func() {
		if err != nil {
			c.setBroken()
		}
	}()

	hs := newServerHandshake(nodeID, keypair)
	err = c.conn.SetDeadline(time.Now().Add(connectionTimeout))
	if err != nil {
		return
	}

	// Consume the client handshake.
	var hsBuf [clientMaxHandshakeLength]byte
	for {
		var n int
		n, err = c.conn.Read(hsBuf[:])
		if err != nil {
			// Yes, just bail out of handshaking even if the Read could have
			// returned data, no point in continuing on EOF/etc.
			return
		}
		c.receiveBuffer.Write(hsBuf[:n])

		var seed []byte
		seed, err = hs.parseClientHandshake(c.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return
		}
		c.receiveBuffer.Reset()

		err = c.conn.SetDeadline(time.Time{})
		if err != nil {
			return
		}

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		c.encoder = framing.NewEncoder(okm[framing.KeyLength:])
		c.decoder = framing.NewDecoder(okm[:framing.KeyLength])

		break
	}

	// Generate/send the response.
	var blob []byte
	blob, err = hs.generateHandshake()
	if err != nil {
		return
	}
	_, err = c.conn.Write(blob)
	if err != nil {
		return
	}
	c.state = stateEstablished

	// Send the PRNG seed as the first packet.
	var frameBuf bytes.Buffer
	err = c.producePacket(&frameBuf, packetTypePrngSeed, c.listener.seed.Bytes()[:], 0)
	if err != nil {
		return
	}
	err = c.padBurst(&frameBuf)
	if err != nil {
		return
	}
	_, err = c.conn.Write(frameBuf.Bytes())

	return
}

func (c *Obfs4Conn) CanHandshake() bool {
	return c.state == stateInit
}

func (c *Obfs4Conn) CanReadWrite() bool {
	return c.state == stateEstablished
}

func (c *Obfs4Conn) ServerHandshake() error {
	// Handshakes when already established are a no-op.
	if c.CanReadWrite() {
		return nil
	} else if !c.CanHandshake() {
		return syscall.EINVAL
	}

	if !c.isServer {
		panic(fmt.Sprintf("BUG: ServerHandshake() called for client connection"))
	}

	// Complete the handshake.
	err := c.serverHandshake(c.listener.nodeID, c.listener.keyPair)
	c.listener = nil
	if err != nil {
		c.closeAfterDelay()
	}

	return err
}

func (c *Obfs4Conn) Read(b []byte) (n int, err error) {
	if !c.CanReadWrite() {
		return 0, syscall.EINVAL
	}

	for c.receiveDecodedBuffer.Len() == 0 {
		_, err = c.consumeFramedPackets(nil)
		if err == framing.ErrAgain {
			continue
		} else if err != nil {
			return
		}
	}

	n, err = c.receiveDecodedBuffer.Read(b)
	return
}

func (c *Obfs4Conn) WriteTo(w io.Writer) (n int64, err error) {
	if !c.CanReadWrite() {
		return 0, syscall.EINVAL
	}

	// If there is buffered payload from earlier Read() calls, write.
	wrLen := 0
	if c.receiveDecodedBuffer.Len() > 0 {
		wrLen, err = w.Write(c.receiveDecodedBuffer.Bytes())
		if err != nil {
			c.setBroken()
			return int64(wrLen), err
		} else if wrLen < int(c.receiveDecodedBuffer.Len()) {
			c.setBroken()
			return int64(wrLen), io.ErrShortWrite
		}
		c.receiveDecodedBuffer.Reset()
	}

	for {
		wrLen, err = c.consumeFramedPackets(w)
		n += int64(wrLen)
		if err == framing.ErrAgain {
			continue
		} else if err != nil {
			// io.EOF is treated as not an error.
			if err == io.EOF {
				err = nil
			}
			break
		}
	}

	return
}

func (c *Obfs4Conn) Write(b []byte) (n int, err error) {
	if !c.CanReadWrite() {
		return 0, syscall.EINVAL
	}

	defer func() {
		if err != nil {
			c.setBroken()
		}
	}()

	// TODO: Change this to write directly to c.conn skipping frameBuf.
	chopBuf := bytes.NewBuffer(b)
	var payload [maxPacketPayloadLength]byte
	var frameBuf bytes.Buffer

	for chopBuf.Len() > 0 {
		// Send maximum sized frames.
		rdLen := 0
		rdLen, err = chopBuf.Read(payload[:])
		if err != nil {
			return 0, err
		} else if rdLen == 0 {
			panic(fmt.Sprintf("BUG: Write(), chopping length was 0"))
		}
		n += rdLen

		err = c.producePacket(&frameBuf, packetTypePayload, payload[:rdLen], 0)
		if err != nil {
			return 0, err
		}
	}

	// Insert random padding.  In theory for some padding lengths, this can be
	// inlined with the payload, but doing it this way simplifies the code
	// significantly.
	err = c.padBurst(&frameBuf)
	if err != nil {
		return 0, err
	}

	// Send the frame(s).
	_, err = c.conn.Write(frameBuf.Bytes())
	if err != nil {
		// Partial writes are fatal because the frame encoder state is advanced
		// at this point.  It's possible to keep frameBuf around, but fuck it.
		// Someone that wants write timeouts can change this.
		return 0, err
	}

	return
}

func (c *Obfs4Conn) Close() error {
	if c.conn == nil {
		return syscall.EINVAL
	}

	c.state = stateClosed

	return c.conn.Close()
}

func (c *Obfs4Conn) LocalAddr() net.Addr {
	if c.state == stateClosed {
		return nil
	}

	return c.conn.LocalAddr()
}

func (c *Obfs4Conn) RemoteAddr() net.Addr {
	if c.state == stateClosed {
		return nil
	}

	return c.conn.RemoteAddr()
}

func (c *Obfs4Conn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (c *Obfs4Conn) SetReadDeadline(t time.Time) error {
	if !c.CanReadWrite() {
		return syscall.EINVAL
	}

	return c.conn.SetReadDeadline(t)
}

func (c *Obfs4Conn) SetWriteDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func Dial(network, address, nodeID, publicKey string) (net.Conn, error) {
	// Decode the node_id/public_key.
	pub, err := ntor.PublicKeyFromBase64(publicKey)
	if err != nil {
		return nil, err
	}
	id, err := ntor.NodeIDFromBase64(nodeID)
	if err != nil {
		return nil, err
	}

	// Generate the initial length obfuscation distribution.
	seed, err := NewDrbgSeed()
	if err != nil {
		return nil, err
	}

	// Connect to the peer.
	c := new(Obfs4Conn)
	c.lenProbDist = newWDist(seed, 0, framing.MaximumSegmentLength)
	c.conn, err = net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	// Handshake.
	err = c.clientHandshake(id, pub)
	if err != nil {
		c.conn.Close()
		return nil, err
	}

	return c, nil
}

// Obfs4Listener a obfs4 network listener.  Servers should use variables of
// type Listener instead of assuming obfs4.
type Obfs4Listener struct {
	listener net.Listener

	keyPair *ntor.Keypair
	nodeID  *ntor.NodeID
	seed    *DrbgSeed
}

func (l *Obfs4Listener) Accept() (net.Conn, error) {
	// Accept a connection.
	c, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}

	// Allocate the obfs4 connection state.
	cObfs := new(Obfs4Conn)
	cObfs.conn = c
	cObfs.isServer = true
	cObfs.listener = l
	cObfs.lenProbDist = newWDist(l.seed, 0, framing.MaximumSegmentLength)
	if err != nil {
		c.Close()
		return nil, err
	}

	return cObfs, nil
}

func (l *Obfs4Listener) Close() error {
	return l.listener.Close()
}

func (l *Obfs4Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *Obfs4Listener) PublicKey() string {
	if l.keyPair == nil {
		return ""
	}

	return l.keyPair.Public().Base64()
}

func Listen(network, laddr, nodeID, privateKey, seed string) (net.Listener, error) {
	var err error

	// Decode node_id/private_key.
	l := new(Obfs4Listener)
	l.keyPair, err = ntor.KeypairFromBase64(privateKey)
	if err != nil {
		return nil, err
	}
	l.nodeID, err = ntor.NodeIDFromBase64(nodeID)
	if err != nil {
		return nil, err
	}
	l.seed, err = DrbgSeedFromBase64(seed)
	if err != nil {
		return nil, err
	}

	// Start up the listener.
	l.listener, err = net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}

	return l, nil
}

/* vim :set ts=4 sw=4 sts=4 noet : */
