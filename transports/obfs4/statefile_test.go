/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
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
	"errors"
	"os"
	"path"
	"testing"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"gitlab.com/yawning/obfs4.git/common/drbg"
	"gitlab.com/yawning/obfs4.git/common/ntor"
)


func TestObfs4StateDir(t *testing.T) {

	nodeID, _ := ntor.NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	serverKeypair, err := ntor.NewKeypair(true)
	if err != nil {
		t.Fatalf("server: ntor.NewKeypair failed: %s", err)
	}

	// We found the mark in the client handshake! We found our registration!
	args := pt.Args{}
	args.Add("node-id", nodeID.Hex())
	args.Add("private-key", serverKeypair.Private().Hex())
	seed, err := drbg.NewSeed()
	if err != nil {
		t.Fatalf("failed to create DRBG seed: %s", err)
	}

	args.Add("drbg-seed", seed.Hex())

	server, err := serverStateFromArgs("", &args)
	if err != nil || server == nil{
		t.Fatalf("serverStateFromArgs failed: %s", err)
	}

	if _, err := os.Stat("./obfs4_state.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file that shouldn't exist either exists or other err occurred: %s", err)
	} else if  _, err := os.Stat("./obfs4_bridgeline.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file that shouldn't exist either exists or other err occurred: %s", err)
	}

	stateDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("failed to make temp dir: %s", err)
	}

	server, err = serverStateFromArgs(stateDir, &args)
	if err != nil || server == nil{
		t.Fatalf("serverStateFromArgs failed: %s", err)
	}

	if _, err := os.Stat(path.Join(stateDir,  "./obfs4_state.json")); err != nil {
		t.Fatalf("file that should exist either doesn't exists or other err occurred: %s", err)
	} else if  _, err := os.Stat(path.Join(stateDir, "./obfs4_bridgeline.txt"));  err != nil {
		t.Fatalf("file that should exist either doesn't exists or other err occurred: %s", err)
	}
}
