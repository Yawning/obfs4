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
//   Bridge obfs4 X.X.X.X:YYYY <Fingerprint> public-key=<Base64 Bridge Public Key> node-id=<Base64 Bridge Node ID>
//   ClientTransportPlugin obfs4 exec obfs4proxy
//
// Server usage (in torrc):
//   BridgeRelay 1
//   ORPort 9001
//   ExtORPort 6669
//   ServerTransportPlugin obfs4 exec obfs4proxy
//   ServerTransportOptions obfs4 private-key=<Base64 Bridge Private Key> node-id=<Base64 Node ID> drbg-seed=<Base64 DRBG Seed>
//
// Because the pluggable transport requires arguments, obfs4proxy requires
// tor-0.2.5.x to be useful.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/yawning/obfs4"
	"github.com/yawning/obfs4/csrand"
	"github.com/yawning/obfs4/ntor"
)

const (
	obfs4Method  = "obfs4"
	obfs4LogFile = "obfs4proxy.log"
)

var enableLogging bool
var unsafeLogging bool
var iatObfuscation bool
var ptListeners []net.Listener

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

func logAndRecover(conn *obfs4.Obfs4Conn) {
	if err := recover(); err != nil {
		log.Printf("[ERROR] %p: Panic: %s", conn, err)
	}
}

func copyLoop(a net.Conn, b *obfs4.Obfs4Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer logAndRecover(b)
		defer wg.Done()
		defer b.Close()
		defer a.Close()

		_, err := io.Copy(b, a)
		if err != nil {
			log.Printf("[WARN] copyLoop: %p: Connection closed: %s", b, err)
		}
	}()
	go func() {
		defer logAndRecover(b)
		defer wg.Done()
		defer a.Close()
		defer b.Close()

		_, err := io.Copy(a, b)
		if err != nil {
			log.Printf("[WARN] copyLoop: %p: Connection closed: %s", b, err)
		}
	}()

	wg.Wait()
}

func serverHandler(conn *obfs4.Obfs4Conn, info *pt.ServerInfo) error {
	defer conn.Close()
	defer logAndRecover(conn)

	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	var addr string
	if unsafeLogging {
		addr = conn.RemoteAddr().String()
	} else {
		addr = "[scrubbed]"
	}

	log.Printf("[INFO] server: %p: New connection from %s", conn, addr)

	// Handshake with the client.
	err := conn.ServerHandshake()
	if err != nil {
		log.Printf("[WARN] server: %p: Handshake failed: %s", conn, err)
		return err
	}

	or, err := pt.DialOr(info, conn.RemoteAddr().String(), obfs4Method)
	if err != nil {
		log.Printf("[ERROR] server: %p: DialOr failed: %s", conn, err)
		return err
	}
	defer or.Close()

	copyLoop(or, conn)

	return nil
}

func serverAcceptLoop(ln *obfs4.Obfs4Listener, info *pt.ServerInfo) error {
	defer ln.Close()
	for {
		conn, err := ln.AcceptObfs4()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go serverHandler(conn, info)
	}
}

func serverSetup() (launched bool) {
	// Initialize pt logging.
	err := ptInitializeLogging(enableLogging)
	if err != nil {
		return
	}

	ptServerInfo, err := pt.ServerSetup([]string{obfs4Method})
	if err != nil {
		return
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
			seed, ok := bindaddr.Options.Get("drbg-seed")
			if !ok {
				pt.SmethodError(bindaddr.MethodName, "needs a drbg-seed option")
				break
			}

			// Initialize the listener.
			ln, err := obfs4.ListenObfs4("tcp", bindaddr.Addr.String(), nodeID,
				privateKey, seed, iatObfuscation)
			if err != nil {
				pt.SmethodError(bindaddr.MethodName, err.Error())
				break
			}

			// Report the SMETHOD including the parameters.
			args := pt.Args{}
			args.Add("node-id", nodeID)
			args.Add("public-key", ln.PublicKey())
			go serverAcceptLoop(ln, &ptServerInfo)
			pt.SmethodArgs(bindaddr.MethodName, ln.Addr(), args)
			ptListeners = append(ptListeners, ln)
			launched = true
		default:
			pt.SmethodError(bindaddr.MethodName, "no such method")
		}
	}
	pt.SmethodsDone()

	return
}

func clientHandler(conn *pt.SocksConn, proxyURI *url.URL) error {
	defer conn.Close()

	var addr string
	if unsafeLogging {
		addr = conn.Req.Target
	} else {
		addr = "[scrubbed]"
	}

	log.Printf("[INFO] client: New connection to %s", addr)

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

	defer logAndRecover(nil)
	dialFn, err := getProxyDialer(proxyURI)
	if err != nil {
		log.Printf("[ERROR] client: failed to get proxy dialer: %s", err)
		conn.Reject()
		return err
	}
	remote, err := obfs4.DialObfs4DialFn(dialFn, "tcp", conn.Req.Target, nodeID, publicKey, iatObfuscation)
	if err != nil {
		log.Printf("[ERROR] client: %p: Handshake failed: %s", remote, err)
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

func clientAcceptLoop(ln *pt.SocksListener, proxyURI *url.URL) error {
	defer ln.Close()
	for {
		conn, err := ln.AcceptSocks()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go clientHandler(conn, proxyURI)
	}
}

func clientSetup() (launched bool) {
	// Initialize pt logging.
	err := ptInitializeLogging(enableLogging)
	if err != nil {
		return
	}

	ptClientInfo, err := pt.ClientSetup([]string{obfs4Method})
	if err != nil {
		log.Fatal(err)
	}

	ptClientProxy, err := ptGetProxy()
	if err != nil {
		log.Fatal(err)
	} else if ptClientProxy != nil {
		ptProxyDone()
	}

	for _, methodName := range ptClientInfo.MethodNames {
		switch methodName {
		case obfs4Method:
			ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
			if err != nil {
				pt.CmethodError(methodName, err.Error())
				break
			}
			go clientAcceptLoop(ln, ptClientProxy)
			pt.Cmethod(methodName, ln.Version(), ln.Addr())
			ptListeners = append(ptListeners, ln)
			launched = true
		default:
			pt.CmethodError(methodName, "no such method")
		}
	}
	pt.CmethodsDone()

	return
}

func ptInitializeLogging(enable bool) error {
	if enable {
		// pt.MakeStateDir will ENV-ERROR for us.
		dir, err := pt.MakeStateDir()
		if err != nil {
			return err
		}

		// While we could just exit, log an ENV-ERROR so it will propagate to
		// the tor log.
		f, err := os.OpenFile(path.Join(dir, obfs4LogFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return ptEnvError(fmt.Sprintf("Failed to open log file: %s\n", err))
		}
		log.SetOutput(f)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	return nil
}

func generateServerParams(id string) {
	idIsFP := id != ""
	var rawID []byte

	if idIsFP {
		var err error
		rawID, err = hex.DecodeString(id)
		if err != nil {
			fmt.Println("Failed to hex decode id:", err)
			return
		}
	} else {
		rawID = make([]byte, ntor.NodeIDLength)
		err := csrand.Bytes(rawID)
		if err != nil {
			fmt.Println("Failed to generate random node-id:", err)
			return
		}
	}
	parsedID, err := ntor.NewNodeID(rawID)
	if err != nil {
		fmt.Println("Failed to parse id:", err)
		return
	}

	fmt.Println("Generated node-id:", parsedID.Base64())

	keypair, err := ntor.NewKeypair(false)
	if err != nil {
		fmt.Println("Failed to generate keypair:", err)
		return
	}

	seed := make([]byte, obfs4.SeedLength)
	err = csrand.Bytes(seed)
	if err != nil {
		fmt.Println("Failed to generate DRBG seed:", err)
		return
	}
	seedBase64 := base64.StdEncoding.EncodeToString(seed)

	fmt.Println("Generated private-key:", keypair.Private().Base64())
	fmt.Println("Generated public-key:", keypair.Public().Base64())
	fmt.Println("Generated drbg-seed:", seedBase64)
	fmt.Println()
	fmt.Println("Client config: ")
	if idIsFP {
		fmt.Printf("  Bridge obfs4 <IP Address:Port> %s node-id=%s public-key=%s\n",
			id, parsedID.Base64(), keypair.Public().Base64())
	} else {
		fmt.Printf("  Bridge obfs4 <IP Address:Port> <Fingerprint> node-id=%s public-key=%s\n",
			parsedID.Base64(), keypair.Public().Base64())
	}
	fmt.Println()
	fmt.Println("Server config:")
	fmt.Printf("  ServerTransportOptions obfs4 node-id=%s private-key=%s drbg-seed=%s\n",
		parsedID.Base64(), keypair.Private().Base64(), seedBase64)
}

func main() {
	// Some command line args.
	genParams := flag.Bool("genServerParams", false, "Generate Bridge operator torrc parameters")
	genParamsFP := flag.String("genServerParamsFP", "", "Optional bridge fingerprint for genServerParams")
	flag.BoolVar(&enableLogging, "enableLogging", false, "Log to TOR_PT_STATE_LOCATION/obfs4proxy.log")
	flag.BoolVar(&iatObfuscation, "iatObfuscation", false, "Enable IAT obufscation (EXPENSIVE)")
	flag.BoolVar(&unsafeLogging, "unsafeLogging", false, "Disable the address scrubber")
	flag.Parse()
	if *genParams {
		generateServerParams(*genParamsFP)
		return
	}

	// Go through the pt protocol and initialize client or server mode.
	launched := false
	isClient, err := ptIsClient()
	if err != nil {
		log.Fatal("[ERROR] obfs4proxy must be run as a managed transport or server")
	} else if isClient {
		launched = clientSetup()
	} else {
		launched = serverSetup()
	}
	if !launched {
		// Something must have failed in client/server setup, just bail.
		os.Exit(-1)
	}

	log.Println("[INFO] obfs4proxy - Launched and listening")
	defer func() {
		log.Println("[INFO] obfs4proxy - Terminated")
	}()

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
