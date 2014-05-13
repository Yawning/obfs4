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
	"encoding/binary"
	"fmt"

	"github.com/yawning/obfs4/framing"
)

const (
	packetOverhead         = 2 + 1
	maxPacketPayloadLength = framing.MaximumFramePayloadLength - packetOverhead
	maxPacketPaddingLength = maxPacketPayloadLength
)

const (
	packetTypePayload = iota
	packetTypePrngSeed
)

// InvalidPacketLengthError is the error returned when decodePacket detects a
// invalid packet length/
type InvalidPacketLengthError int

func (e InvalidPacketLengthError) Error() string {
	return fmt.Sprintf("packet: Invalid packet length: %d", int(e))
}

// InvalidPayloadLengthError is the error returned when decodePacket rejects the
// payload length.
type InvalidPayloadLengthError int

func (e InvalidPayloadLengthError) Error() string {
	return fmt.Sprintf("packet: Invalid payload length: %d", int(e))
}

var zeroPadBytes [maxPacketPaddingLength]byte

func makePacket(pkt []byte, pktType uint8, data []byte, padLen uint16) int {
	pktLen := packetOverhead + len(data) + int(padLen)

	if len(data)+int(padLen) > maxPacketPayloadLength {
		panic(fmt.Sprintf("BUG: makePacket() len(data) + padLen > maxPacketPayloadLength: %d + %d > %d",
			len(data), padLen, maxPacketPayloadLength))
	}

	// Packets are:
	//   uint8_t type      packetTypePayload (0x00)
	//   uint16_t length   Length of the payload (Big Endian).
	//   uint8_t[] payload Data payload.
	//   uint8_t[] padding Padding.

	pkt[0] = pktType
	binary.BigEndian.PutUint16(pkt[1:], uint16(len(data)))
	if len(data) > 0 {
		copy(pkt[3:], data[:])
	}
	copy(pkt[3+len(data):], zeroPadBytes[:padLen])

	return pktLen
}

func (c *Obfs4Conn) makeAndEncryptPacket(pktType uint8, data []byte, padLen uint16) (int, []byte, error) {
	var pkt [framing.MaximumFramePayloadLength]byte

	// Wrap the payload in a packet.
	n := makePacket(pkt[:], pktType, data[:], padLen)

	// Encode the packet in an AEAD frame.
	n, frame, err := c.encoder.Encode(pkt[:n])
	return n, frame, err
}

func (c *Obfs4Conn) decodePacket(pkt []byte) error {
	if len(pkt) < packetOverhead {
		return InvalidPacketLengthError(len(pkt))
	}

	pktType := pkt[0]
	payloadLen := binary.BigEndian.Uint16(pkt[1:])
	if int(payloadLen) > len(pkt)-packetOverhead {
		return InvalidPayloadLengthError(int(payloadLen))
	}

	payload := pkt[3 : 3+payloadLen]
	switch pktType {
	case packetTypePayload:
		if len(payload) > 0 {
			c.receiveDecodedBuffer.Write(payload)
		}
	case packetTypePrngSeed:
		if len(payload) == distSeedLength {
			c.probDist.reset(payload)
		}
	default:
		// Ignore unrecognised packet types.
	}

	return nil
}

/* vim :set ts=4 sw=4 sts=4 noet : */
