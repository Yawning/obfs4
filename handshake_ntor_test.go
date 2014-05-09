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
	"testing"

	"github.com/yawning/obfs4/ntor"
)

func TestHandshakeNtor(t *testing.T) {
	// Generate the server node id and id keypair.
	nodeID, _ := ntor.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	idKeypair, _ := ntor.NewKeypair(false)

	// Intialize the client and server handshake states
	clientHs, err := newClientHandshake(nodeID, idKeypair.Public())
	if err != nil {
		t.Fatal("newClientHandshake failed:", err)
	}
	serverHs := newServerHandshake(nodeID, idKeypair)

	// Generate what the client will send to the server.
	cToS, err := clientHs.generateHandshake()
	if err != nil {
		t.Fatal("clientHandshake.generateHandshake() failed", err)
	}

	// Parse the client handshake message.
	serverSeed, err := serverHs.parseClientHandshake(cToS)
	if err != nil {
		t.Fatal("serverHandshake.parseClientHandshake() failed", err)
	}

	// Genrate what the server will send to the client.
	sToC, err := serverHs.generateHandshake()
	if err != nil {
		t.Fatal("serverHandshake.generateHandshake() failed", err)
	}

	// Parse the server handshake message.
	n, clientSeed, err := clientHs.parseServerHandshake(sToC)
	if err != nil {
		t.Fatal("clientHandshake.parseServerHandshake() failed", err)
	}
	if n != len(sToC) {
		t.Fatalf("clientHandshake.parseServerHandshake() has bytes remaining: %d", n)
	}

	// Ensure the derived shared secret is the same.
	if 0 != bytes.Compare(clientSeed, serverSeed) {
		t.Fatalf("client/server seed mismatch")
	}
}
