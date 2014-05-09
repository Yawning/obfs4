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
 *
 * This file is based off goptlib's dummy-server.go file.
 */

// obfs4 pluggable transport server. Works only as a managed proxy.
//
// Usage (in torrc):
// 	BridgeRelay 1
// 	ORPort 9001
// 	ExtORPort 6669
// 	ServerTransportPlugin obfs4 exec obfs4-server
//  ServerTransportOptions obfs4 private-key=<Base64 Bridge private key> node-id=<Base64 Node ID>
//
// Becuase the pluggable transport requires arguments, using obfs4-server
// requires tor 0.2.5.x.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/yawning/obfs4"
	"github.com/yawning/obfs4/ntor"
)

import "git.torproject.org/pluggable-transports/goptlib.git"

var ptInfo pt.ServerInfo

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

func copyLoop(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(b, a)
		wg.Done()
	}()
	go func() {
		io.Copy(a, b)
		wg.Done()
	}()

	wg.Wait()
}

func handler(conn net.Conn) error {
	defer conn.Close()

	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	or, err := pt.DialOr(&ptInfo, conn.RemoteAddr().String(), "obfs4")
	if err != nil {
		return err
	}
	defer or.Close()

	copyLoop(conn, or)

	return nil
}

func acceptLoop(ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go handler(conn)
	}
}

func generateParams(id string) {
	rawID, err := hex.DecodeString(id)
	if err != nil {
		fmt.Println("Failed to hex decode id:", err)
		return
	}

	parsedID, err := ntor.NewNodeID(rawID)
	if err != nil {
		fmt.Println("Failed to parse id:", err)
		return
	}

	fmt.Println("Generated node_id:", parsedID.Base64())

	keypair, err := ntor.NewKeypair(false)
	if err != nil {
		fmt.Println("Failed to generate keypair:", err)
		return
	}

	fmt.Println("Generated private-key:", keypair.Private().Base64())
	fmt.Println("Generated public-key:", keypair.Public().Base64())
}

func main() {
	var err error

	// Some command line args.
	genParams := flag.String("gen", "", "Generate params given a Node ID.")
	flag.Parse()
	if *genParams != "" {
		generateParams(*genParams)
		os.Exit(0)
	}

	// Ok, guess we're in PT land.
	ptInfo, err = pt.ServerSetup([]string{"obfs4"})
	if err != nil {
		os.Exit(1)
	}

	listeners := make([]net.Listener, 0)
	for _, bindaddr := range ptInfo.Bindaddrs {
		switch bindaddr.MethodName {
		case "obfs4":
			// Handle the mandetory arguments.
			privateKey, ok := bindaddr.Options.Get("private-key")
			if !ok {
				pt.SmethodError(bindaddr.MethodName, "need a private-key option")
				break
			}
			nodeID, ok := bindaddr.Options.Get("node-id")
			if !ok {
				pt.SmethodError(bindaddr.MethodName, "need a node-id option")
				break
			}

			ln, err := obfs4.Listen("tcp", bindaddr.Addr.String(), nodeID,
									privateKey)
			if err != nil {
				pt.SmethodError(bindaddr.MethodName, err.Error())
				break
			}

			oLn, _ := ln.(*obfs4.Obfs4Listener)
			args := pt.Args{}
			args.Add("node-id", nodeID)
			args.Add("public-key", oLn.PublicKey())
			go acceptLoop(ln)
			pt.SmethodArgs(bindaddr.MethodName, ln.Addr(), args)
			// TODO: Maybe log the args?
			listeners = append(listeners, ln)
		default:
			pt.SmethodError(bindaddr.MethodName, "no such method")
		}
	}
	pt.SmethodsDone()

	var numHandlers int = 0
	var sig os.Signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// wait for first signal
	sig = nil
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}
	for _, ln := range listeners {
		ln.Close()
	}

	if sig == syscall.SIGTERM {
		return
	}

	// wait for second signal or no more handlers
	sig = nil
	for sig == nil && numHandlers != 0 {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}
}
