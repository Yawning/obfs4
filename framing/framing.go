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

//
// Package framing implements the obfs4 link framing and cryptography.
//
// The Encoder/Decoder shared secret format is:
//    uint8_t[32] NaCl SecretBox key
//    uint8_t[24] NaCl Nonce prefix
//    uint8_t[16] SipHash-2-4 key (used to obfsucate length)
//
// The frame format is:
//   uint16_t length (obfsucated, big endian)
//   NaCl SecretBox (Poly1305/XSalsa20) containing:
//     uint8_t[16] tag (Part of the SecretBox construct)
//     uint8_t[]   payload
//
// The length field is length of the NaCl SecretBox XORed with the truncated
// SipHash-2-4 digest of the previous SecretBox concatenated with the nonce
// used to seal the current SecretBox.
//
// The NaCl SecretBox (Poly1305/XSalsa20) nonce format is:
//     uint8_t[24] prefix (Fixed)
//     uint64_t    counter (Big endian)
//
// The counter is initialized to 1, and is incremented on each frame.  Since
// the protocol is designed to be used over a reliable medium, the nonce is not
// transmitted over the wire as both sides of the conversation know the prefix
// and the initial counter value.  It is imperative that the counter does not
// wrap, and sessions MUST terminate before 2^64 frames are sent.
//
package framing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"code.google.com/p/go.crypto/nacl/secretbox"

	"github.com/dchest/siphash"
)

const (
	// MaximumSegmentLength is the length of the largest possible segment
	// including overhead.
	MaximumSegmentLength = 1500 - 40

	// FrameOverhead is the length of the framing overhead.
	FrameOverhead = lengthLength + secretbox.Overhead

	// MaximumFramePayloadLength is the length of the maximum allowed payload
	// per frame.
	MaximumFramePayloadLength = MaximumSegmentLength - FrameOverhead

	// KeyLength is the length of the Encoder/Decoder secret key.
	KeyLength = keyLength + noncePrefixLength + 16

	maxFrameLength = MaximumSegmentLength - lengthLength
	minFrameLength = FrameOverhead - lengthLength

	keyLength = 32

	noncePrefixLength  = 16
	nonceCounterLength = 8
	nonceLength        = noncePrefixLength + nonceCounterLength

	lengthLength = 2
)

// Error returned when Decoder.Decode() requires more data to continue.
var ErrAgain = errors.New("framing: More data needed to decode")

// Error returned when Decoder.Decode() failes to authenticate a frame.
var ErrTagMismatch = errors.New("framing: Poly1305 tag mismatch")

// Error returned when the NaCl SecretBox nonce's counter wraps (FATAL).
var ErrNonceCounterWrapped = errors.New("framing: Nonce counter wrapped")

// InvalidPayloadLengthError is the error returned when Encoder.Encode()
// rejects the payload length.
type InvalidPayloadLengthError int

func (e InvalidPayloadLengthError) Error() string {
	return fmt.Sprintf("framing: Invalid payload length: %d", int(e))
}

// InvalidFrameLengthError is the error returned when Decoder.Decode()
// rejects the payload length.
type InvalidFrameLengthError int

func (e InvalidFrameLengthError) Error() string {
	return fmt.Sprintf("framing: Invalid frame length: %d", int(e))
}

type boxNonce struct {
	prefix  [noncePrefixLength]byte
	counter uint64
}

func (nonce *boxNonce) init(prefix []byte) {
	if noncePrefixLength != len(prefix) {
		panic(fmt.Sprintf("BUG: Nonce prefix length invalid: %d", len(prefix)))
	}

	copy(nonce.prefix[:], prefix)
	nonce.counter = 1
}

func (nonce boxNonce) bytes(out *[nonceLength]byte) error {
	// The security guarantee of Poly1305 is broken if a nonce is ever reused
	// for a given key.  Detect this by checking for counter wraparound since
	// we start each counter at 1.  If it ever happens that more than 2^64 - 1
	// frames are transmitted over a given connection, support for rekeying
	// will be neccecary, but that's unlikely to happen.
	if nonce.counter == 0 {
		return ErrNonceCounterWrapped
	}

	copy(out[:], nonce.prefix[:])
	binary.BigEndian.PutUint64(out[noncePrefixLength:], nonce.counter)

	return nil
}

// Encoder is a frame encoder instance.
type Encoder struct {
	key   [keyLength]byte
	sip   hash.Hash64
	nonce boxNonce
}

// NewEncoder creates a new Encoder instance.  It must be supplied a slice
// containing exactly KeyLength bytes of keying material.
func NewEncoder(key []byte) *Encoder {
	if len(key) != KeyLength {
		panic(fmt.Sprintf("BUG: Invalid encoder key length: %d", len(key)))
	}

	encoder := new(Encoder)
	copy(encoder.key[:], key[0:keyLength])
	encoder.nonce.init(key[keyLength : keyLength+noncePrefixLength])
	encoder.sip = siphash.New(key[keyLength+noncePrefixLength:])

	return encoder
}

// Encode encodes a single frame worth of payload and returns the encoded
// length and the resulting frame.  InvalidPayloadLengthError is recoverable,
// all other errors MUST be treated as fatal and the session aborted.
func (encoder *Encoder) Encode(payload []byte) (int, []byte, error) {
	payloadLen := len(payload)
	if MaximumFramePayloadLength < payloadLen {
		return 0, nil, InvalidPayloadLengthError(payloadLen)
	}

	// Generate a new nonce.
	var nonce [nonceLength]byte
	err := encoder.nonce.bytes(&nonce)
	if err != nil {
		return 0, nil, err
	}
	encoder.nonce.counter++

	// Encrypt and MAC payload.
	var box []byte
	box = secretbox.Seal(nil, payload, &nonce, &encoder.key)

	// Obfuscate the length.
	length := uint16(len(box))
	encoder.sip.Write(nonce[:])
	lengthMask := encoder.sip.Sum(nil)
	encoder.sip.Reset()
	length ^= binary.BigEndian.Uint16(lengthMask)
	var obfsLen [lengthLength]byte
	binary.BigEndian.PutUint16(obfsLen[:], length)

	// Prepare the next obfsucator.
	encoder.sip.Write(box)

	// Return the frame.
	return payloadLen + FrameOverhead, append(obfsLen[:], box...), nil
}

// Decoder is a frame decoder instance.
type Decoder struct {
	key   [keyLength]byte
	nonce boxNonce
	sip   hash.Hash64

	nextNonce  [nonceLength]byte
	nextLength uint16
}

// NewDecoder creates a new Decoder instance.  It must be supplied a slice
// containing exactly KeyLength bytes of keying material.
func NewDecoder(key []byte) *Decoder {
	if len(key) != KeyLength {
		panic(fmt.Sprintf("BUG: Invalid decoder key length: %d", len(key)))
	}

	decoder := new(Decoder)
	copy(decoder.key[:], key[0:keyLength])
	decoder.nonce.init(key[keyLength : keyLength+noncePrefixLength])
	decoder.sip = siphash.New(key[keyLength+noncePrefixLength:])

	return decoder
}

// Decode decodes a stream of data and returns the length and decoded frame if
// any.  ErrAgain is a temporary failure, all other errors MUST be treated as
// fatal and the session aborted.
func (decoder *Decoder) Decode(data *bytes.Buffer) (int, []byte, error) {
	// A length of 0 indicates that we do not know how big the next frame is
	// going to be.
	if decoder.nextLength == 0 {
		// Attempt to pull out the next frame length.
		if lengthLength > data.Len() {
			return 0, nil, ErrAgain
		}

		// Remove the length field from the buffer.
		var obfsLen [lengthLength]byte
		n, err := data.Read(obfsLen[:])
		if err != nil {
			return 0, nil, err
		} else if n != lengthLength {
			// Should *NEVER* happen, since at least 2 bytes exist.
			panic(fmt.Sprintf("BUG: Failed to read obfuscated length: %d", n))
		}

		// Derive the nonce the peer used.
		err = decoder.nonce.bytes(&decoder.nextNonce)
		if err != nil {
			return 0, nil, err
		}

		// Deobfuscate the length field.
		length := binary.BigEndian.Uint16(obfsLen[:])
		decoder.sip.Write(decoder.nextNonce[:])
		lengthMask := decoder.sip.Sum(nil)
		decoder.sip.Reset()
		length ^= binary.BigEndian.Uint16(lengthMask)
		if maxFrameLength < length || minFrameLength > length {
			return 0, nil, InvalidFrameLengthError(length)
		}
		decoder.nextLength = length
	}

	if int(decoder.nextLength) > data.Len() {
		return 0, nil, ErrAgain
	}

	// Unseal the frame.
	box := make([]byte, decoder.nextLength)
	n, err := data.Read(box)
	if err != nil {
		return 0, nil, err
	} else if n != int(decoder.nextLength) {
		// Should *NEVER* happen, since at least 2 bytes exist.
		panic(fmt.Sprintf("BUG: Failed to read secretbox, got %d, should have %d",
						  n, decoder.nextLength))
	}
	out, ok := secretbox.Open(nil, box, &decoder.nextNonce, &decoder.key)
	if !ok {
		return 0, nil, ErrTagMismatch
	}
	decoder.sip.Write(box)

	// Clean up and prepare for the next frame.
	decoder.nextLength = 0
	decoder.nonce.counter++

	return len(out), out, nil
}

/* vim :set ts=4 sw=4 sts=4 noet : */
