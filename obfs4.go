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
	defaultReadSize   = framing.MaximumSegmentLength
	connectionTimeout = time.Duration(15) * time.Second

	minCloseThreshold = 0
	maxCloseThreshold = framing.MaximumSegmentLength * 5
	minCloseInterval  = 0
	maxCloseInterval  = 60
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

	isOk     bool
	isServer bool

	// Server side state.
	listener *Obfs4Listener
}

func (c *Obfs4Conn) calcPadLen(burstLen int) int {
	tailLen := burstLen % framing.MaximumSegmentLength
	toPadTo := c.lenProbDist.sample()

	ret := 0
	if toPadTo >= tailLen {
		ret = toPadTo - tailLen
	} else {
		ret = (framing.MaximumSegmentLength - tailLen) + toPadTo
	}

	return ret
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
	buf := make([]byte, defaultReadSize)
	for discarded < int(toDiscard) {
		n, err := c.conn.Read(buf)
		if err != nil {
			return
		}
		discarded += n
	}
}

func (c *Obfs4Conn) clientHandshake(nodeID *ntor.NodeID, publicKey *ntor.PublicKey) error {
	if c.isServer {
		panic(fmt.Sprintf("BUG: clientHandshake() called for server connection"))
	}

	// Generate/send the client handshake.
	hs, err := newClientHandshake(nodeID, publicKey)
	if err != nil {
		return err
	}
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}

	err = c.conn.SetDeadline(time.Now().Add(connectionTimeout * 2))
	if err != nil {
		return err
	}

	_, err = c.conn.Write(blob)
	if err != nil {
		return err
	}

	// Consume the server handshake.
	hsBuf := make([]byte, serverMaxHandshakeLength)
	for {
		n, err := c.conn.Read(hsBuf)
		if err != nil {
			return err
		}
		c.receiveBuffer.Write(hsBuf[:n])

		n, seed, err := hs.parseServerHandshake(c.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		_ = c.receiveBuffer.Next(n)

		err = c.conn.SetDeadline(time.Time{})
		if err != nil {
			return err
		}

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		c.encoder = framing.NewEncoder(okm[:framing.KeyLength])
		c.decoder = framing.NewDecoder(okm[framing.KeyLength:])

		c.isOk = true

		return nil
	}
}

func (c *Obfs4Conn) serverHandshake(nodeID *ntor.NodeID, keypair *ntor.Keypair) error {
	if !c.isServer {
		panic(fmt.Sprintf("BUG: serverHandshake() called for client connection"))
	}

	hs := newServerHandshake(nodeID, keypair)
	err := c.conn.SetDeadline(time.Now().Add(connectionTimeout))
	if err != nil {
		return err
	}

	// Consume the client handshake.
	hsBuf := make([]byte, clientMaxHandshakeLength)
	for {
		n, err := c.conn.Read(hsBuf)
		if err != nil {
			return err
		}
		c.receiveBuffer.Write(hsBuf[:n])

		seed, err := hs.parseClientHandshake(c.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		c.receiveBuffer.Reset()

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		c.encoder = framing.NewEncoder(okm[framing.KeyLength:])
		c.decoder = framing.NewDecoder(okm[:framing.KeyLength])

		break
	}

	// Generate/send the response.
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	_, err = c.conn.Write(blob)
	if err != nil {
		return err
	}

	err = c.conn.SetDeadline(time.Time{})
	if err != nil {
		return err
	}

	c.isOk = true

	// TODO: Generate/send the PRNG seed.

	return nil
}

func (c *Obfs4Conn) ServerHandshake() error {
	// Handshakes when already established are a no-op.
	if c.isOk {
		return nil
	}

	// Clients handshake as part of Dial.
	if !c.isServer {
		panic(fmt.Sprintf("BUG: ServerHandshake() called for client connection"))
	}

	// Regardless of what happens, don't need the listener past returning from
	// this routine.
	defer func() {
		c.listener = nil
	}()

	// Complete the handshake.
	err := c.serverHandshake(c.listener.nodeID, c.listener.keyPair)
	if err != nil {
		c.closeAfterDelay()
	}

	return err
}

func (c *Obfs4Conn) Read(b []byte) (n int, err error) {
	if !c.isOk {
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
	if !c.isOk {
		return 0, syscall.EINVAL
	}

	wrLen := 0

	// If there is buffered payload from earlier Read() calls, write.
	if c.receiveDecodedBuffer.Len() > 0 {
		wrLen, err = w.Write(c.receiveDecodedBuffer.Bytes())
		if wrLen < int(c.receiveDecodedBuffer.Len()) {
			c.isOk = false
			return int64(wrLen), io.ErrShortWrite
		} else if err != nil {
			c.isOk = false
			return int64(wrLen), err
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

func (c *Obfs4Conn) Write(b []byte) (int, error) {
	chopBuf := bytes.NewBuffer(b)
	buf := make([]byte, maxPacketPayloadLength)
	nSent := 0
	var frameBuf bytes.Buffer

	for chopBuf.Len() > 0 {
		// Send maximum sized frames.
		n, err := chopBuf.Read(buf)
		if err != nil {
			c.isOk = false
			return 0, err
		} else if n == 0 {
			panic(fmt.Sprintf("BUG: Write(), chopping length was 0"))
		}
		nSent += n

		_, frame, err := c.makeAndEncryptPacket(packetTypePayload, buf[:n], 0)
		if err != nil {
			c.isOk = false
			return 0, err
		}

		frameBuf.Write(frame)
	}

	// Insert random padding.  In theory it's possible to inline padding for
	// certain framesizes into the last AEAD packet, but always sending 1 or 2
	// padding frames is considerably easier.
	padLen := c.calcPadLen(frameBuf.Len())
	if padLen > 0 {
		if padLen > headerLength {
			_, frame, err := c.makeAndEncryptPacket(packetTypePayload, []byte{},
				uint16(padLen-headerLength))
			if err != nil {
				c.isOk = false
				return 0, err
			}
			frameBuf.Write(frame)
		} else {
			_, frame, err := c.makeAndEncryptPacket(packetTypePayload, []byte{},
				maxPacketPayloadLength)
			if err != nil {
				c.isOk = false
				return 0, err
			}
			frameBuf.Write(frame)

			_, frame, err = c.makeAndEncryptPacket(packetTypePayload, []byte{},
				uint16(padLen))
			if err != nil {
				c.isOk = false
				return 0, err
			}
			frameBuf.Write(frame)
		}
	}

	// Send the frame(s).
	_, err := c.conn.Write(frameBuf.Bytes())
	if err != nil {
		// Partial writes are fatal because the frame encoder state is advanced
		// at this point.  It's possible to keep frameBuf around, but fuck it.
		// Someone that wants write timeouts can change this.
		c.isOk = false
		return 0, err
	}

	return nSent, nil
}

func (c *Obfs4Conn) Close() error {
	if c.conn == nil {
		return syscall.EINVAL
	}

	c.isOk = false

	return c.conn.Close()
}

func (c *Obfs4Conn) LocalAddr() net.Addr {
	if !c.isOk {
		return nil
	}

	return c.conn.LocalAddr()
}

func (c *Obfs4Conn) RemoteAddr() net.Addr {
	if !c.isOk {
		return nil
	}

	return c.conn.RemoteAddr()
}

func (c *Obfs4Conn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (c *Obfs4Conn) SetReadDeadline(t time.Time) error {
	if !c.isOk {
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

	// Connect to the peer.
	c := new(Obfs4Conn)
	c.lenProbDist, err = newWDist(nil, 0, framing.MaximumSegmentLength)
	if err != nil {
		return nil, err
	}
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
	cObfs.lenProbDist, err = newWDist(nil, 0, framing.MaximumSegmentLength)
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

func Listen(network, laddr, nodeID, privateKey string) (net.Listener, error) {
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

	// Start up the listener.
	l.listener, err = net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}

	return l, nil
}

/* vim :set ts=4 sw=4 sts=4 noet : */
