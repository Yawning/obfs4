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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"git.torproject.org/pluggable-transports/obfs4.git/common/csrand"
	"git.torproject.org/pluggable-transports/obfs4.git/common/drbg"
	"git.torproject.org/pluggable-transports/obfs4.git/common/ntor"
)

const (
	stateFile = "obfs4_state.json"
)

type jsonServerState struct {
	NodeID     string `json:"node-id"`
	PrivateKey string `json:"private-key"`
	PublicKey  string `json:"public-key"`
	DrbgSeed   string `json:"drbg-seed"`
}

type obfs4ServerState struct {
	nodeID      *ntor.NodeID
	identityKey *ntor.Keypair
	drbgSeed    *drbg.Seed
}

func serverStateFromArgs(stateDir string, args *pt.Args) (*obfs4ServerState, error) {
	var js jsonServerState
	var nodeIDOk, privKeyOk, seedOk bool

	js.NodeID, nodeIDOk = args.Get(nodeIDArg)
	js.PrivateKey, privKeyOk = args.Get(privateKeyArg)
	js.DrbgSeed, seedOk = args.Get(seedArg)

	if !privKeyOk && !nodeIDOk && !seedOk {
		if err := jsonServerStateFromFile(stateDir, &js); err != nil {
			return nil, err
		}
	} else if !privKeyOk {
		return nil, fmt.Errorf("missing argument '%s'", privateKeyArg)
	} else if !nodeIDOk {
		return nil, fmt.Errorf("missing argument '%s'", nodeIDArg)
	} else if !seedOk {
		return nil, fmt.Errorf("missing argument '%s'", seedArg)
	}

	return serverStateFromJSONServerState(&js)
}

func serverStateFromJSONServerState(js *jsonServerState) (*obfs4ServerState, error) {
	var err error

	st := new(obfs4ServerState)
	if st.nodeID, err = ntor.NodeIDFromBase64(js.NodeID); err != nil {
		return nil, err
	}
	if st.identityKey, err = ntor.KeypairFromBase64(js.PrivateKey); err != nil {
		return nil, err
	}
	var rawSeed []byte
	if rawSeed, err = base64.StdEncoding.DecodeString(js.DrbgSeed); err != nil {
		return nil, err
	}
	if st.drbgSeed, err = drbg.SeedFromBytes(rawSeed); err != nil {
		return nil, err
	}

	return st, nil
}

func jsonServerStateFromFile(stateDir string, js *jsonServerState) error {
	f, err := ioutil.ReadFile(path.Join(stateDir, stateFile))
	if err != nil {
		if os.IsNotExist(err) {
			if err = newJSONServerState(stateDir, js); err == nil {
				return nil
			}
		}
		return err
	}

	if err = json.Unmarshal(f, js); err != nil {
		return err
	}

	return nil
}

func newJSONServerState(stateDir string, js *jsonServerState) (err error) {
	// Generate everything a server needs, using the cryptographic PRNG.
	var st obfs4ServerState
	rawID := make([]byte, ntor.NodeIDLength)
	if err = csrand.Bytes(rawID); err != nil {
		return
	}
	if st.nodeID, err = ntor.NewNodeID(rawID); err != nil {
		return
	}
	if st.identityKey, err = ntor.NewKeypair(false); err != nil {
		return
	}
	if st.drbgSeed, err = drbg.NewSeed(); err != nil {
		return
	}

	// Encode it into JSON format and write the state file.
	js.NodeID = st.nodeID.Base64()
	js.PrivateKey = st.identityKey.Private().Base64()
	js.PublicKey = st.identityKey.Public().Base64()
	js.DrbgSeed = st.drbgSeed.Base64()

	var encoded []byte
	if encoded, err = json.Marshal(js); err != nil {
		return
	}

	if err = ioutil.WriteFile(path.Join(stateDir, stateFile), encoded, 0600); err != nil {
		return err
	}

	return nil
}
