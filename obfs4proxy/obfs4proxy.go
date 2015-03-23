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

// Go language Tor Pluggable Transport suite.  Works only as a managed
// client/server.
package main

import (
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

	"golang.org/x/net/proxy"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"git.torproject.org/pluggable-transports/obfs4.git/transports"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"
)

const (
	obfs4proxyVersion = "0.0.4"
	obfs4proxyLogFile = "obfs4proxy.log"
	socksAddr         = "127.0.0.1:0"
	elidedAddr        = "[scrubbed]"
)

var enableLogging bool
var unsafeLogging bool
var stateDir string
var handlerChan chan int

// DialFn is a function pointer to a function that matches the net.Dialer.Dial
// interface.
type DialFn func(string, string) (net.Conn, error)

func elideAddr(addrStr string) string {
	if unsafeLogging {
		return addrStr
	}

	if addr, err := resolveAddrStr(addrStr); err == nil {
		// Only scrub off the address so that it's slightly easier to follow
		// the logs by looking at the port.
		return fmt.Sprintf("%s:%d", elidedAddr, addr.Port)
	}

	return elidedAddr
}

func elideError(err error) string {
	// Go's net package is somewhat rude and includes IP address and port
	// information in the string representation of net.Errors.  Figure out if
	// this is the case here, and sanitize the error messages as needed.
	if unsafeLogging {
		return err.Error()
	}

	// If err is not a net.Error, just return the string representation,
	// presumably transport authors know what they are doing.
	netErr, ok := err.(net.Error)
	if !ok {
		return err.Error()
	}

	switch t := netErr.(type) {
	case *net.AddrError:
		return t.Err + " " + elidedAddr
	case *net.DNSError:
		return "lookup " + elidedAddr + " on " + elidedAddr + ": " + t.Err
	case *net.InvalidAddrError:
		return "invalid address error"
	case *net.UnknownNetworkError:
		return "unknown network " + elidedAddr
	case *net.OpError:
		return t.Op + ": " + t.Err.Error()
	default:
		// For unknown error types, do the conservative thing and only log the
		// type of the error instead of assuming that the string representation
		// does not contain sensitive information.
		return fmt.Sprintf("network error: <%T>", t)
	}
}

func clientSetup() (launched bool, listeners []net.Listener) {
	ptClientInfo, err := pt.ClientSetup(transports.Transports())
	if err != nil {
		log.Fatal(err)
	}

	ptClientProxy, err := ptGetProxy()
	if err != nil {
		log.Fatal(err)
	} else if ptClientProxy != nil {
		ptProxyDone()
	}

	// Launch each of the client listeners.
	for _, name := range ptClientInfo.MethodNames {
		t := transports.Get(name)
		if t == nil {
			pt.CmethodError(name, "no such transport is supported")
			continue
		}

		f, err := t.ClientFactory(stateDir)
		if err != nil {
			pt.CmethodError(name, "failed to get ClientFactory")
			continue
		}

		ln, err := pt.ListenSocks("tcp", socksAddr)
		if err != nil {
			pt.CmethodError(name, err.Error())
			continue
		}

		go clientAcceptLoop(f, ln, ptClientProxy)
		pt.Cmethod(name, ln.Version(), ln.Addr())

		infof("%s - registered listener: %s", name, ln.Addr())

		listeners = append(listeners, ln)
		launched = true
	}
	pt.CmethodsDone()

	return
}

func clientAcceptLoop(f base.ClientFactory, ln *pt.SocksListener, proxyURI *url.URL) error {
	defer ln.Close()
	for {
		conn, err := ln.AcceptSocks()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go clientHandler(f, conn, proxyURI)
	}
}

func clientHandler(f base.ClientFactory, conn *pt.SocksConn, proxyURI *url.URL) {
	defer conn.Close()
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	name := f.Transport().Name()
	addrStr := elideAddr(conn.Req.Target)
	infof("%s(%s) - new connection", name, addrStr)

	// Deal with arguments.
	args, err := f.ParseArgs(&conn.Req.Args)
	if err != nil {
		errorf("%s(%s) - invalid arguments: %s", name, addrStr, err)
		conn.Reject()
		return
	}

	// Obtain the proxy dialer if any, and create the outgoing TCP connection.
	var dialFn DialFn
	if proxyURI == nil {
		dialFn = proxy.Direct.Dial
	} else {
		// This is unlikely to happen as the proxy protocol is verified during
		// the configuration phase.
		dialer, err := proxy.FromURL(proxyURI, proxy.Direct)
		if err != nil {
			errorf("%s(%s) - failed to obtain proxy dialer: %s", name, addrStr, elideError(err))
			conn.Reject()
			return
		}
		dialFn = dialer.Dial
	}
	remoteConn, err := dialFn("tcp", conn.Req.Target) // XXX: Allow UDP?
	if err != nil {
		errorf("%s(%s) - outgoing connection failed: %s", name, addrStr, elideError(err))
		conn.Reject()
		return
	}
	defer remoteConn.Close()

	// Instantiate the client transport method, handshake, and start pushing
	// bytes back and forth.
	remote, err := f.WrapConn(remoteConn, args)
	if err != nil {
		errorf("%s(%s) - handshake failed: %s", name, addrStr, elideError(err))
		conn.Reject()
		return
	}
	err = conn.Grant(remoteConn.RemoteAddr().(*net.TCPAddr))
	if err != nil {
		errorf("%s(%s) - SOCKS grant failed: %s", name, addrStr, elideError(err))
		return
	}

	if err = copyLoop(conn, remote); err != nil {
		warnf("%s(%s) - closed connection: %s", name, addrStr, elideError(err))
	} else {
		infof("%s(%s) - closed connection", name, addrStr)
	}

	return
}

func serverSetup() (launched bool, listeners []net.Listener) {
	ptServerInfo, err := pt.ServerSetup(transports.Transports())
	if err != nil {
		log.Fatal(err)
	}

	for _, bindaddr := range ptServerInfo.Bindaddrs {
		name := bindaddr.MethodName
		t := transports.Get(name)
		if t == nil {
			pt.SmethodError(name, "no such transport is supported")
			continue
		}

		f, err := t.ServerFactory(stateDir, &bindaddr.Options)
		if err != nil {
			pt.SmethodError(name, err.Error())
			continue
		}

		ln, err := net.ListenTCP("tcp", bindaddr.Addr)
		if err != nil {
			pt.SmethodError(name, err.Error())
			continue
		}

		go serverAcceptLoop(f, ln, &ptServerInfo)
		if args := f.Args(); args != nil {
			pt.SmethodArgs(name, ln.Addr(), *args)
		} else {
			pt.SmethodArgs(name, ln.Addr(), nil)
		}

		infof("%s - registered listener: %s", name, elideAddr(ln.Addr().String()))

		listeners = append(listeners, ln)
		launched = true
	}
	pt.SmethodsDone()

	return
}

func serverAcceptLoop(f base.ServerFactory, ln net.Listener, info *pt.ServerInfo) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go serverHandler(f, conn, info)
	}
}

func serverHandler(f base.ServerFactory, conn net.Conn, info *pt.ServerInfo) {
	defer conn.Close()
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	name := f.Transport().Name()
	addrStr := elideAddr(conn.RemoteAddr().String())
	infof("%s(%s) - new connection", name, addrStr)

	// Instantiate the server transport method and handshake.
	remote, err := f.WrapConn(conn)
	if err != nil {
		warnf("%s(%s) - handshake failed: %s", name, addrStr, elideError(err))
		return
	}

	// Connect to the orport.
	orConn, err := pt.DialOr(info, conn.RemoteAddr().String(), name)
	if err != nil {
		errorf("%s(%s) - failed to connect to ORPort: %s", name, addrStr, elideError(err))
		return
	}
	defer orConn.Close()

	if err = copyLoop(orConn, remote); err != nil {
		warnf("%s(%s) - closed connection: %s", name, addrStr, elideError(err))
	} else {
		infof("%s(%s) - closed connection", name, addrStr)
	}

	return
}

func copyLoop(a net.Conn, b net.Conn) error {
	// Note: b is always the pt connection.  a is the SOCKS/ORPort connection.
	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer b.Close()
		defer a.Close()
		_, err := io.Copy(b, a)
		errChan <- err
	}()
	go func() {
		defer wg.Done()
		defer a.Close()
		defer b.Close()
		_, err := io.Copy(a, b)
		errChan <- err
	}()

	// Wait for both upstream and downstream to close.  Since one side
	// terminating closes the other, the second error in the channel will be
	// something like EINVAL (though io.Copy() will swallow EOF), so only the
	// first error is returned.
	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}

	return nil
}

func ptInitializeLogging(enable bool) error {
	if enable {
		// While we could just exit, log an ENV-ERROR so it will propagate to
		// the tor log.
		f, err := os.OpenFile(path.Join(stateDir, obfs4proxyLogFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return ptEnvError(fmt.Sprintf("failed to open log file: %s\n", err))
		}
		log.SetOutput(f)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	return nil
}

func getVersion() string {
	return fmt.Sprintf("obfs4proxy-%s", obfs4proxyVersion)
}

func main() {
	// Handle the command line arguments.
	_, execName := path.Split(os.Args[0])
	showVer := flag.Bool("version", false, "Print version and exit")
	logLevelStr := flag.String("logLevel", "ERROR", "Log level (ERROR/WARN/INFO)")
	flag.BoolVar(&enableLogging, "enableLogging", false, "Log to TOR_PT_STATE_LOCATION/"+obfs4proxyLogFile)
	flag.BoolVar(&unsafeLogging, "unsafeLogging", false, "Disable the address scrubber")
	flag.Parse()

	if *showVer {
		fmt.Printf("%s\n", getVersion())
		os.Exit(0)
	}
	if err := setLogLevel(*logLevelStr); err != nil {
		log.Fatalf("[ERROR]: failed to set log level: %s", err)
	}

	// Determine if this is a client or server, initialize logging, and finish
	// the pt configuration.
	var ptListeners []net.Listener
	handlerChan = make(chan int)
	launched := false
	isClient, err := ptIsClient()
	if err != nil {
		log.Fatalf("[ERROR]: %s - must be run as a managed transport", execName)
	}
	if stateDir, err = pt.MakeStateDir(); err != nil {
		log.Fatalf("[ERROR]: %s - No state directory: %s", execName, err)
	}
	if err = ptInitializeLogging(enableLogging); err != nil {
		log.Fatalf("[ERROR]: %s - failed to initialize logging", execName)
	} else {
		noticef("%s - launched", getVersion())
	}
	if isClient {
		infof("%s - initializing client transport listeners", execName)
		launched, ptListeners = clientSetup()
	} else {
		infof("%s - initializing server transport listeners", execName)
		launched, ptListeners = serverSetup()
	}
	if !launched {
		// Initialization failed, the client or server setup routines should
		// have logged, so just exit here.
		os.Exit(-1)
	}

	infof("%s - accepting connections", execName)
	defer func() {
		noticef("%s - terminated", execName)
	}()

	// At this point, the pt config protocol is finished, and incoming
	// connections will be processed.  Per the pt spec, on sane platforms
	// termination is signaled via SIGINT (or SIGTERM), so wait on tor to
	// request a shutdown of some sort.

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for the first SIGINT (close listeners).
	var sig os.Signal
	numHandlers := 0
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
			if sig == syscall.SIGTERM {
				// SIGTERM causes immediate termination.
				return
			}
		}
	}
	for _, ln := range ptListeners {
		ln.Close()
	}

	// Wait for the 2nd SIGINT (or a SIGTERM), or for all current sessions to
	// finish.
	sig = nil
	for sig == nil && numHandlers != 0 {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}
}
