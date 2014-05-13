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

package obfs4

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"time"

	"github.com/yawning/obfs4/framing"
	"github.com/yawning/obfs4/ntor"
)

const (
	clientMinPadLength       = serverMinHandshakeLength - clientMinHandshakeLength
	clientMaxPadLength       = framing.MaximumSegmentLength - clientMinHandshakeLength
	clientMinHandshakeLength = ntor.RepresentativeLength + markLength + macLength
	clientMaxHandshakeLength = framing.MaximumSegmentLength

	serverMinPadLength       = 0
	serverMaxPadLength       = framing.MaximumSegmentLength - serverMinHandshakeLength
	serverMinHandshakeLength = ntor.RepresentativeLength + ntor.AuthLength +
		markLength + macLength
	serverMaxHandshakeLength = framing.MaximumSegmentLength

	markLength = sha256.Size
	macLength  = sha256.Size
)

var ErrMarkNotFoundYet = errors.New("handshake: M_[C,S] not found yet")
var ErrInvalidHandshake = errors.New("handshake: Failed to find M_[C,S]")
var ErrNtorFailed = errors.New("handshake: ntor handshake failure")

type InvalidMacError struct {
	Derived  []byte
	Received []byte
}

func (e *InvalidMacError) Error() string {
	return fmt.Sprintf("handshake: MAC mismatch: Dervied: %s Received: %s.",
		hex.EncodeToString(e.Derived), hex.EncodeToString(e.Received))
}

type InvalidAuthError struct {
	Derived  *ntor.Auth
	Received *ntor.Auth
}

func (e *InvalidAuthError) Error() string {
	return fmt.Sprintf("handshake: ntor AUTH mismatch: Derived: %s Received:%s.",
		hex.EncodeToString(e.Derived.Bytes()[:]),
		hex.EncodeToString(e.Received.Bytes()[:]))
}

type clientHandshake struct {
	keypair        *ntor.Keypair
	nodeID         *ntor.NodeID
	serverIdentity *ntor.PublicKey
	epochHour      []byte

	mac hash.Hash

	serverRepresentative *ntor.Representative
	serverAuth           *ntor.Auth
	serverMark           []byte
}

func newClientHandshake(nodeID *ntor.NodeID, serverIdentity *ntor.PublicKey) (*clientHandshake, error) {
	var err error

	hs := new(clientHandshake)
	hs.keypair, err = ntor.NewKeypair(true)
	if err != nil {
		return nil, err
	}
	hs.nodeID = nodeID
	hs.serverIdentity = serverIdentity
	hs.mac = hmac.New(sha256.New, hs.serverIdentity.Bytes()[:])

	return hs, nil
}

func (hs *clientHandshake) generateHandshake() ([]byte, error) {
	var buf bytes.Buffer

	hs.mac.Reset()
	hs.mac.Write(hs.keypair.Representative().Bytes()[:])
	mark := hs.mac.Sum(nil)

	// The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
	//  * X is the client's ephemeral Curve25519 public key representative.
	//  * P_C is [0,clientMaxPadLength] bytes of random padding.
	//  * M_C is HMAC-SHA256(serverIdentity, X)
	//  * MAC is HMAC-SHA256(serverIdentity, X .... E)
	//  * E is the string representation of the number of hours since the UNIX
	//    epoch.

	// Generate the padding
	pad, err := makePad(clientMinPadLength, clientMaxPadLength)
	if err != nil {
		return nil, err
	}

	// Write X, P_C, M_C.
	buf.Write(hs.keypair.Representative().Bytes()[:])
	buf.Write(pad)
	buf.Write(mark)

	// Calculate and write the MAC.
	hs.mac.Reset()
	hs.mac.Write(buf.Bytes())
	hs.epochHour = []byte(strconv.FormatInt(getEpochHour(), 10))
	hs.mac.Write(hs.epochHour)
	buf.Write(hs.mac.Sum(nil))

	return buf.Bytes(), nil
}

func (hs *clientHandshake) parseServerHandshake(resp []byte) (int, []byte, error) {
	// No point in examining the data unless the miminum plausible response has
	// been received.
	if serverMinHandshakeLength > len(resp) {
		return 0, nil, ErrMarkNotFoundYet
	}

	if hs.serverRepresentative == nil || hs.serverAuth == nil {
		// Pull out the representative/AUTH. (XXX: Add ctors to ntor)
		hs.serverRepresentative = new(ntor.Representative)
		copy(hs.serverRepresentative.Bytes()[:], resp[0:ntor.RepresentativeLength])
		hs.serverAuth = new(ntor.Auth)
		copy(hs.serverAuth.Bytes()[:], resp[ntor.RepresentativeLength:])

		// Derive the mark
		hs.mac.Reset()
		hs.mac.Write(hs.serverRepresentative.Bytes()[:])
		hs.serverMark = hs.mac.Sum(nil)
	}

	// Attempt to find the mark + MAC.
	pos := findMark(hs.serverMark, resp,
		ntor.RepresentativeLength+ntor.AuthLength, serverMaxHandshakeLength)
	if pos == -1 {
		if len(resp) >= serverMaxHandshakeLength {
			return 0, nil, ErrInvalidHandshake
		}
		return 0, nil, ErrMarkNotFoundYet
	}

	// Validate the MAC.
	hs.mac.Reset()
	hs.mac.Write(resp[:pos+markLength])
	hs.mac.Write(hs.epochHour)
	macCmp := hs.mac.Sum(nil)
	macRx := resp[pos+markLength : pos+markLength+macLength]
	if !hmac.Equal(macCmp, macRx) {
		return 0, nil, &InvalidMacError{macCmp, macRx}
	}

	// Complete the handshake.
	serverPublic := hs.serverRepresentative.ToPublic()
	ok, seed, auth := ntor.ClientHandshake(hs.keypair, serverPublic,
		hs.serverIdentity, hs.nodeID)
	if !ok {
		return 0, nil, ErrNtorFailed
	}
	if !ntor.CompareAuth(auth, hs.serverAuth.Bytes()[:]) {
		return 0, nil, &InvalidAuthError{auth, hs.serverAuth}
	}

	return pos + markLength + macLength, seed.Bytes()[:], nil
}

type serverHandshake struct {
	keypair        *ntor.Keypair
	nodeID         *ntor.NodeID
	serverIdentity *ntor.Keypair
	epochHour      []byte
	serverAuth     *ntor.Auth

	mac hash.Hash

	clientRepresentative *ntor.Representative
	clientMark           []byte
}

func newServerHandshake(nodeID *ntor.NodeID, serverIdentity *ntor.Keypair) *serverHandshake {
	hs := new(serverHandshake)
	hs.nodeID = nodeID
	hs.serverIdentity = serverIdentity
	hs.mac = hmac.New(sha256.New, hs.serverIdentity.Public().Bytes()[:])

	return hs
}

func (hs *serverHandshake) parseClientHandshake(resp []byte) ([]byte, error) {
	// No point in examining the data unless the miminum plausible response has
	// been received.
	if clientMinHandshakeLength > len(resp) {
		return nil, ErrMarkNotFoundYet
	}

	if hs.clientRepresentative == nil {
		// Pull out the representative/AUTH. (XXX: Add ctors to ntor)
		hs.clientRepresentative = new(ntor.Representative)
		copy(hs.clientRepresentative.Bytes()[:], resp[0:ntor.RepresentativeLength])

		// Derive the mark
		hs.mac.Reset()
		hs.mac.Write(hs.clientRepresentative.Bytes()[:])
		hs.clientMark = hs.mac.Sum(nil)
	}

	// Attempt to find the mark + MAC.
	pos := findMark(hs.clientMark, resp, ntor.RepresentativeLength,
		serverMaxHandshakeLength)
	if pos == -1 {
		if len(resp) >= clientMaxHandshakeLength {
			return nil, ErrInvalidHandshake
		}
		return nil, ErrMarkNotFoundYet
	}

	// Validate the MAC.
	macFound := false
	for _, off := range []int64{0, -1, 1} {
		// Allow epoch to be off by up to a hour in either direction.
		epochHour := []byte(strconv.FormatInt(getEpochHour()+int64(off), 10))
		hs.mac.Reset()
		hs.mac.Write(resp[:pos+markLength])
		hs.mac.Write(epochHour)
		macCmp := hs.mac.Sum(nil)
		macRx := resp[pos+markLength : pos+markLength+macLength]
		if hmac.Equal(macCmp, macRx) {
			macFound = true
			hs.epochHour = epochHour

			// In theory, we should always evaluate all 3 MACs, but at this
			// point we are reasonably confident that the client knows the
			// correct NodeID/Public key, and if this fails, we just ignore the
			// client for a random interval and drop the connection anyway.
			break
		}
	}
	if !macFound {
		// This probably should be an InvalidMacError, but conveying the 3 MACS
		// that would be accepted is annoying so just return a generic fatal
		// failure.
		return nil, ErrInvalidHandshake
	}

	// Client should never sent trailing garbage.
	if len(resp) != pos+markLength+macLength {
		return nil, ErrInvalidHandshake
	}

	// At this point the client knows that we exist, so do the keypair
	// generation and complete our side of the handshake.
	var err error
	hs.keypair, err = ntor.NewKeypair(true)
	if err != nil {
		return nil, err
	}

	clientPublic := hs.clientRepresentative.ToPublic()
	ok, seed, auth := ntor.ServerHandshake(clientPublic, hs.keypair,
		hs.serverIdentity, hs.nodeID)
	if !ok {
		return nil, ErrNtorFailed
	}
	hs.serverAuth = auth

	return seed.Bytes()[:], nil
}

func (hs *serverHandshake) generateHandshake() ([]byte, error) {
	var buf bytes.Buffer

	hs.mac.Reset()
	hs.mac.Write(hs.keypair.Representative().Bytes()[:])
	mark := hs.mac.Sum(nil)

	// The server handshake is Y | AUTH | P_S | M_S | MAC(Y | AUTH | P_S | M_S | E) where:
	//  * Y is the server's ephemeral Curve25519 public key representative.
	//  * AUTH is the ntor handshake AUTH value.
	//  * P_S is [0,serverMaxPadLength] bytes of random padding.
	//  * M_S is HMAC-SHA256(serverIdentity, Y)
	//  * MAC is HMAC-SHA256(serverIdentity, Y .... E)
	//  * E is the string representation of the number of hours since the UNIX
	//    epoch.

	// Generate the padding
	pad, err := makePad(serverMinPadLength, serverMaxPadLength)
	if err != nil {
		return nil, err
	}

	// Write Y, AUTH, P_S, M_S.
	buf.Write(hs.keypair.Representative().Bytes()[:])
	buf.Write(hs.serverAuth.Bytes()[:])
	buf.Write(pad)
	buf.Write(mark)

	// Calculate and write the MAC.
	hs.mac.Reset()
	hs.mac.Write(buf.Bytes())
	hs.epochHour = []byte(strconv.FormatInt(getEpochHour(), 10))
	hs.mac.Write(hs.epochHour)
	buf.Write(hs.mac.Sum(nil))

	return buf.Bytes(), nil
}

// getEpochHour returns the number of hours since the UNIX epoch.
func getEpochHour() int64 {
	return time.Now().Unix() / 3600
}

func findMark(mark, buf []byte, startPos, maxPos int) int {
	endPos := len(buf)
	if endPos > maxPos {
		endPos = maxPos
	}

	// XXX: bytes.Index() uses a naive search, which kind of sucks.
	pos := bytes.Index(buf[startPos:endPos], mark)
	if pos == -1 {
		return -1
	}

	// Return the index relative to the start of the slice.
	return pos + startPos
}

func makePad(min, max int) ([]byte, error) {
	padLen := randRange(min, max)
	pad := make([]byte, padLen)
	_, err := rand.Read(pad)
	if err != nil {
		return nil, err
	}

	return pad, err
}

/* vim :set ts=4 sw=4 sts=4 noet : */
