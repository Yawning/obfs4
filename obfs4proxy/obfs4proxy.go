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
 * This file is based off goptlib's dummy-[client,server].go files.
 */

// obfs4 pluggable transport.  Works only as a managed proxy.
//
// Client usage (in torrc):
//   UseBridges 1
//   Bridge obfs4 X.X.X.X:YYYY public-key=<Base64 Bridge public key> node-id=<Base64 Bridge Node ID>
//   ClientTransportPlugin obfs4 exec obfs4proxy
//
// Server usage (in torrc):
//   BridgeRelay 1
//   ORPort 9001
//   ExtORPort 6669
//   ServerTransportPlugin obfs4 exec obfs4proxy
//   ServerTransportOptions obfs4 private-key=<Base64 Bridge private key> node-id=<Base64 Node ID>
//
// Because the pluggable transport requires arguments, obfs4proxy requires
// tor-0.2.5.x to be useful.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"

	"git.torproject.org/pluggable-transports/goptlib"
	"github.com/yawning/obfs4"
	"github.com/yawning/obfs4/ntor"
)

const (
	obfs4Method  = "obfs4"
	obfs4LogFile = "obfs4proxy.log"
)

var ptListeners []net.Listener

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

func logAndRecover() {
	if err := recover(); err != nil {
		log.Println("[ERROR] Panic:", err)
	}
}

func copyLoop(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer logAndRecover()
		defer wg.Done()
		defer b.Close()
		defer a.Close()

		_, err := io.Copy(b, a)
		if err != nil {
			log.Printf("[WARN] Connection closed: %s", err)
		}
	}()
	go func() {
		defer logAndRecover()
		defer wg.Done()
		defer a.Close()
		defer b.Close()

		_, err := io.Copy(a, b)
		if err != nil {
			log.Printf("[WARN] Connection closed: %s", err)
		}
	}()

	wg.Wait()
}

func serverHandler(conn net.Conn, info *pt.ServerInfo) error {
	defer conn.Close()
	defer logAndRecover()

	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	// Handshake with the client.
	oConn, _ := conn.(*obfs4.Obfs4Conn)
	err := oConn.ServerHandshake()
	if err != nil {
		log.Printf("[WARN] server: Handshake failed: %s", err)
		return err
	}

	or, err := pt.DialOr(info, conn.RemoteAddr().String(), obfs4Method)
	if err != nil {
		log.Printf("[ERROR] server: DialOr failed: %s", err)
		return err
	}
	defer or.Close()

	copyLoop(or, conn)

	return nil
}

func serverAcceptLoop(ln net.Listener, info *pt.ServerInfo) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go serverHandler(conn, info)
	}
}

func serverSetup() bool {
	launch := false
	var err error

	ptServerInfo, err := pt.ServerSetup([]string{obfs4Method})
	if err != nil {
		return launch
	}

	for _, bindaddr := range ptServerInfo.Bindaddrs {
		switch bindaddr.MethodName {
		case obfs4Method:
			// Handle the mandetory arguments.
			privateKey, ok := bindaddr.Options.Get("private-key")
			if !ok {
				pt.SmethodError(bindaddr.MethodName, "needs a private-key option")
				break
			}
			nodeID, ok := bindaddr.Options.Get("node-id")
			if !ok {
				pt.SmethodError(bindaddr.MethodName, "needs a node-id option")
				break
			}

			// Initialize the listener.
			ln, err := obfs4.Listen("tcp", bindaddr.Addr.String(), nodeID,
				privateKey)
			if err != nil {
				pt.SmethodError(bindaddr.MethodName, err.Error())
				break
			}

			// Report the SMETHOD including the parameters.
			oLn, _ := ln.(*obfs4.Obfs4Listener)
			args := pt.Args{}
			args.Add("node-id", nodeID)
			args.Add("public-key", oLn.PublicKey())
			go serverAcceptLoop(ln, &ptServerInfo)
			pt.SmethodArgs(bindaddr.MethodName, ln.Addr(), args)
			ptListeners = append(ptListeners, ln)
			launch = true
		default:
			pt.SmethodError(bindaddr.MethodName, "no such method")
		}
	}
	pt.SmethodsDone()

	return launch
}

func clientHandler(conn *pt.SocksConn) error {
	defer conn.Close()

	// Extract the peer's node ID and public key.
	nodeID, ok := conn.Req.Args.Get("node-id")
	if !ok {
		log.Printf("[ERROR] client: missing node-id argument")
		conn.Reject()
		return nil
	}
	publicKey, ok := conn.Req.Args.Get("public-key")
	if !ok {
		log.Printf("[ERROR] client: missing public-key argument")
		conn.Reject()
		return nil
	}

	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	defer logAndRecover()
	remote, err := obfs4.Dial("tcp", conn.Req.Target, nodeID, publicKey)
	if err != nil {
		log.Printf("[ERROR] client: Handshake failed: %s", err)
		conn.Reject()
		return err
	}
	defer remote.Close()
	err = conn.Grant(remote.RemoteAddr().(*net.TCPAddr))
	if err != nil {
		return err
	}

	copyLoop(conn, remote)

	return nil
}

func clientAcceptLoop(ln *pt.SocksListener) error {
	defer ln.Close()
	for {
		conn, err := ln.AcceptSocks()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go clientHandler(conn)
	}
}

func clientSetup() bool {
	launch := false

	ptClientInfo, err := pt.ClientSetup([]string{obfs4Method})
	if err != nil {
		log.Fatal(err)
		return launch
	}

	for _, methodName := range ptClientInfo.MethodNames {
		switch methodName {
		case obfs4Method:
			ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
			if err != nil {
				pt.CmethodError(methodName, err.Error())
				break
			}
			go clientAcceptLoop(ln)
			pt.Cmethod(methodName, ln.Version(), ln.Addr())
			ptListeners = append(ptListeners, ln)
			launch = true
		default:
			pt.CmethodError(methodName, "no such method")
		}
	}
	pt.CmethodsDone()

	return launch
}

func ptIsClient() bool {
	env := os.Getenv("TOR_PT_CLIENT_TRANSPORTS")
	return env != ""
}

func ptIsServer() bool {
	env := os.Getenv("TOR_PT_SERVER_TRANSPORTS")
	return env != ""
}

func ptGetStateDir() (dir string, err error) {
	dir = os.Getenv("TOR_PT_STATE_LOCATION")
	if dir == "" {
		return
	}

	err = os.MkdirAll(dir, 0755)
	if err != nil {
		log.Fatalf("[ERROR] Failed to create path: %s", err)
	}

	return
}

func ptInitializeLogging() {
	dir, err := ptGetStateDir()
	if err != nil || dir == "" {
		return
	}

	f, err := os.OpenFile(path.Join(dir, obfs4LogFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("[ERROR] Failed to open log file: %s", err)
	}
	log.SetOutput(f)
}

func generateServerParams(id string) {
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
	// Some command line args.
	genParams := flag.String("gen", "", "Generate params given a Node ID.")
	flag.Parse()
	if *genParams != "" {
		generateServerParams(*genParams)
		os.Exit(0)
	}

	// Initialize pt logging.
	ptInitializeLogging()

	// Go through the pt protocol and initialize client or server mode.
	launched := false
	if ptIsClient() {
		launched = clientSetup()
	} else if ptIsServer() {
		launched = serverSetup()
	}
	if !launched {
		log.Fatal("[ERROR] obfs4proxy must be run as a managed transport or server")
	}

	log.Println("[INFO] obfs4proxy - Launched and listening")

	// Handle termination notification.
	numHandlers := 0
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
	for _, ln := range ptListeners {
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

/* vim :set ts=4 sw=4 sts=4 noet : */
