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

// Package obfs4 implements the obfs4 protocol.  For the most part, obfs4
// connections are exposed via the net.Conn and net.Listener interface, though
// accepting connections as a server requires calling ServerHandshake on the
// conn to finish connection establishment.
package obfs4

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"syscall"
	"time"

	"github.com/yawning/obfs4/framing"
	"github.com/yawning/obfs4/ntor"
)

const (
	headerLength      = framing.FrameOverhead + packetOverhead
	connectionTimeout = time.Duration(30) * time.Second

	maxCloseDelayBytes = framing.MaximumSegmentLength * 5
	maxCloseDelay      = 60
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
	listener  *Obfs4Listener
	startTime time.Time
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

	delay := time.Duration(c.listener.closeDelay)*time.Second + connectionTimeout
	deadline := c.startTime.Add(delay)
	if time.Now().After(deadline) {
		return
	}

	err := c.conn.SetReadDeadline(deadline)
	if err != nil {
		return
	}

	// Consume and discard data on this connection until either the specified
	// interval passes or a certain size has been reached.
	discarded := 0
	var buf [framing.MaximumSegmentLength]byte
	for discarded < int(c.listener.closeDelayBytes) {
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

	//
	// Since the current and only implementation always sends a PRNG seed for
	// the length obfuscation, this makes the amount of data received from the
	// server inconsistent with the length sent from the client.
	//
	// Rebalance this by tweaking the client mimimum padding/server maximum
	// padding, and sending the PRNG seed unpadded (As in, treat the PRNG seed
	// as part of the server response).  See inlineSeedFrameLength in
	// handshake_ntor.go.
	//

	// Generate/send the response.
	var blob []byte
	blob, err = hs.generateHandshake()
	if err != nil {
		return
	}
	var frameBuf bytes.Buffer
	_, err = frameBuf.Write(blob)
	if err != nil {
		return
	}
	c.state = stateEstablished

	// Send the PRNG seed as the first packet.
	err = c.producePacket(&frameBuf, packetTypePrngSeed, c.listener.seed.Bytes()[:], 0)
	if err != nil {
		return
	}
	_, err = c.conn.Write(frameBuf.Bytes())
	if err != nil {
		return
	}

	return
}

// CanHandshake queries the connection state to see if it is appropriate to
// call ServerHandshake to complete connection establishment.
func (c *Obfs4Conn) CanHandshake() bool {
	return c.state == stateInit
}

// CanReadWrite queries the connection state to see if it is possible to read
// and write data.
func (c *Obfs4Conn) CanReadWrite() bool {
	return c.state == stateEstablished
}

// ServerHandshake completes the server side of the obfs4 handshake.  Servers
// are required to call this after accepting a connection.  ServerHandshake
// will treat errors encountered during the handshake as fatal and drop the
// connection before returning.
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
	if err != nil {
		c.closeAfterDelay()
	}
	c.listener = nil

	return err
}

// Read implements the net.Conn Read method.
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

// WriteTo implements the io.WriterTo WriteTo method.
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

// Write implements the net.Conn Write method.  The obfs4 lengt obfuscation is
// done based on the amount of data passed to Write (each call to Write results
// in up to 2 frames of padding).  Passing excessively short buffers to Write
// will result in significant overhead.
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

// Close closes the connection.
func (c *Obfs4Conn) Close() error {
	if c.conn == nil {
		return syscall.EINVAL
	}

	c.state = stateClosed

	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *Obfs4Conn) LocalAddr() net.Addr {
	if c.state == stateClosed {
		return nil
	}

	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Obfs4Conn) RemoteAddr() net.Addr {
	if c.state == stateClosed {
		return nil
	}

	return c.conn.RemoteAddr()
}

// SetDeadline is a convoluted way to get syscall.ENOTSUP.
func (c *Obfs4Conn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.  Connections
// must be in the established state (CanReadWrite).
func (c *Obfs4Conn) SetReadDeadline(t time.Time) error {
	if !c.CanReadWrite() {
		return syscall.EINVAL
	}

	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline is a convoluted way to get syscall.ENOTSUP.
func (c *Obfs4Conn) SetWriteDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

// DialObfs4 connects to the remote address on the network, and handshakes with
// the peer's obfs4 Node ID and Identity Public Key.  nodeID and publicKey are
// expected as strings containing the Base64 encoded values.
func DialObfs4(network, address, nodeID, publicKey string) (*Obfs4Conn, error) {
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

// Obfs4Listener is the implementation of the net.Listener interface for obfs4
// connections.
type Obfs4Listener struct {
	listener net.Listener

	keyPair *ntor.Keypair
	nodeID  *ntor.NodeID

	seed *DrbgSeed

	closeDelayBytes int
	closeDelay      int
}

// Accept implements the Accept method of the net.Listener interface; it waits
// for the next call and returns a generic net.Conn.  Callers are responsible
// for completing the handshake by calling Obfs4Conn.ServerHandshake().
func (l *Obfs4Listener) Accept() (net.Conn, error) {
	conn, err := l.AcceptObfs4()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// AcceptObfs4 accepts the next incoming call and returns a new connection.
// Callers are responsible for completing the handshake by calling
// Obfs4Conn.ServerHandshake().
func (l *Obfs4Listener) AcceptObfs4() (*Obfs4Conn, error) {
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
	cObfs.startTime = time.Now()

	return cObfs, nil
}

// Close stops listening on the Obfs4 endpoint.  Already Accepted connections
// are not closed.
func (l *Obfs4Listener) Close() error {
	return l.listener.Close()
}

// Addr returns the listener's network address.
func (l *Obfs4Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// PublicKey returns the listener's Identity Public Key, a Base64 encoded
// obfs4.ntor.PublicKey.
func (l *Obfs4Listener) PublicKey() string {
	if l.keyPair == nil {
		return ""
	}

	return l.keyPair.Public().Base64()
}

// NodeID returns the listener's NodeID, a Base64 encoded obfs4.ntor.NodeID.
func (l *Obfs4Listener) NodeID() string {
	if l.nodeID == nil {
		return ""
	}

	return l.nodeID.Base64()
}

// ListenObfs4 annnounces on the network and address, and returns and
// Obfs4Listener. nodeId, privateKey and seed are expected as strings
// containing the Base64 encoded values.
func ListenObfs4(network, laddr, nodeID, privateKey, seed string) (*Obfs4Listener, error) {
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

	rng := rand.New(newHashDrbg(l.seed))
	l.closeDelayBytes = rng.Intn(maxCloseDelayBytes)
	l.closeDelay = rng.Intn(maxCloseDelay)

	// Start up the listener.
	l.listener, err = net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}

	return l, nil
}

/* vim :set ts=4 sw=4 sts=4 noet : */
