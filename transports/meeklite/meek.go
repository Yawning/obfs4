/*
 * Copyright (c) 2015, Yawning Angel <yawning at schwanenlied dot me>
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

package meeklite

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	gourl "net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"gitlab.com/yawning/obfs4.git/transports/base"
	utls "gitlab.com/yawning/utls.git"
)

const (
	urlArg         = "url"
	frontArg       = "front"
	utlsArg        = "utls"
	disableHPKPArg = "disableHPKP"

	maxChanBacklog = 16

	// Constants shamelessly stolen from meek-client.go...
	maxPayloadLength       = 0x10000
	initPollInterval       = 100 * time.Millisecond
	maxPollInterval        = 5 * time.Second
	pollIntervalMultiplier = 1.5
	maxRetries             = 10
	retryDelay             = 30 * time.Second
)

var (
	// ErrNotSupported is the error returned for a unsupported operation.
	ErrNotSupported = errors.New("meek_lite: operation not supported")

	loopbackAddr = net.IPv4(127, 0, 0, 1)
)

type meekClientArgs struct {
	url   *gourl.URL
	front string

	utls        *utls.ClientHelloID
	disableHPKP bool
}

func (ca *meekClientArgs) Network() string {
	return transportName
}

func (ca *meekClientArgs) String() string {
	return transportName + ":" + ca.front + ":" + ca.url.String()
}

func newClientArgs(args *pt.Args) (ca *meekClientArgs, err error) {
	ca = &meekClientArgs{}

	// Parse the URL argument.
	str, ok := args.Get(urlArg)
	if !ok {
		return nil, fmt.Errorf("missing argument '%s'", urlArg)
	}
	ca.url, err = gourl.Parse(str)
	if err != nil {
		return nil, fmt.Errorf("malformed url: '%s'", str)
	}
	switch ca.url.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("invalid scheme: '%s'", ca.url.Scheme)
	}

	// Parse the (optional) front argument.
	ca.front, _ = args.Get(frontArg)

	// Parse the (optional) utls argument.
	utlsOpt, _ := args.Get(utlsArg)
	if ca.utls, err = parseClientHelloID(utlsOpt); err != nil {
		return nil, err
	}

	// Parse the (optional) HPKP disable argument.
	hpkpOpt, _ := args.Get(disableHPKPArg)
	if strings.ToLower(hpkpOpt) == "true" {
		ca.disableHPKP = true
	}

	return ca, nil
}

type meekConn struct {
	args         *meekClientArgs
	sessionID    string
	roundTripper http.RoundTripper

	closeOnce       sync.Once
	workerWrChan    chan []byte
	workerRdChan    chan []byte
	workerCloseChan chan struct{}
	rdBuf           *bytes.Buffer
}

func (c *meekConn) Read(p []byte) (n int, err error) {
	// If there is data left over from the previous read,
	// service the request using the buffered data.
	if c.rdBuf != nil {
		if c.rdBuf.Len() == 0 {
			panic("empty read buffer")
		}
		n, err = c.rdBuf.Read(p)
		if c.rdBuf.Len() == 0 {
			c.rdBuf = nil
		}
		return
	}

	// Wait for the worker to enqueue more incoming data.
	b, ok := <-c.workerRdChan
	if !ok {
		// Close() was called and the worker's shutting down.
		return 0, io.ErrClosedPipe
	}

	// Ew, an extra copy, but who am I kidding, it's meek.
	buf := bytes.NewBuffer(b)
	n, err = buf.Read(p)
	if buf.Len() > 0 {
		// If there's data pending, stash the buffer so the next
		// Read() call will use it to fulfuill the Read().
		c.rdBuf = buf
	}
	return
}

func (c *meekConn) Write(b []byte) (n int, err error) {
	// Check to see if the connection is actually open.
	select {
	case <-c.workerCloseChan:
		return 0, io.ErrClosedPipe
	default:
	}

	if len(b) == 0 {
		return 0, nil
	}

	// Copy the data to be written to a new slice, since
	// we return immediately after queuing and the peer can
	// happily reuse `b` before data has been sent.
	b2 := append([]byte{}, b...)
	if ok := c.enqueueWrite(b2); !ok {
		// Technically we did enqueue data, but the worker's
		// got closed out from under us.
		return 0, io.ErrClosedPipe
	}
	runtime.Gosched()
	return len(b), nil
}

func (c *meekConn) Close() error {
	err := os.ErrClosed

	c.closeOnce.Do(func() {
		// Tear down the worker, if it is still running.
		close(c.workerCloseChan)
		err = nil
	})

	return err
}

func (c *meekConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: loopbackAddr}
}

func (c *meekConn) RemoteAddr() net.Addr {
	return c.args
}

func (c *meekConn) SetDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *meekConn) SetReadDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *meekConn) SetWriteDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *meekConn) enqueueWrite(b []byte) (ok bool) {
	defer func() {
		if err := recover(); err != nil {
			ok = false
		}
	}()
	c.workerWrChan <- b
	return true
}

func (c *meekConn) roundTrip(sndBuf []byte) (recvBuf []byte, err error) {
	var req *http.Request
	var resp *http.Response

	for retries := 0; retries < maxRetries; retries++ {
		url := *c.args.url
		host := url.Host
		if c.args.front != "" {
			url.Host = c.args.front
		}
		var body io.Reader
		if len(sndBuf) > 0 {
			body = bytes.NewReader(sndBuf)
		}
		req, err = http.NewRequest("POST", url.String(), body)
		if err != nil {
			return nil, err
		}
		if c.args.front != "" {
			req.Host = host
		}
		req.Header.Set("X-Session-Id", c.sessionID)
		req.Header.Set("User-Agent", "")

		resp, err = c.roundTripper.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			recvBuf, err = ioutil.ReadAll(io.LimitReader(resp.Body, maxPayloadLength))
			resp.Body.Close()
			return
		}

		resp.Body.Close()
		err = fmt.Errorf("status code was %d, not %d", resp.StatusCode, http.StatusOK)
		time.Sleep(retryDelay)
	}
	return
}

func (c *meekConn) ioWorker() {
	interval := initPollInterval
	var sndBuf, leftBuf []byte

loop:
	for {
		sndBuf = nil
		select {
		case <-time.After(interval):
			// If the poll interval has elapsed, issue a request.
		case sndBuf = <-c.workerWrChan:
			// If there is data pending a send, issue a request.
		case <-c.workerCloseChan:
			break loop
		}

		// Combine short writes as long as data is available to be
		// sent immediately and it will not put us over the max
		// payload limit.  Any excess data is stored and dispatched
		// as the next request).
		sndBuf = append(leftBuf, sndBuf...)
		wrSz := len(sndBuf)
		for len(c.workerWrChan) > 0 && wrSz < maxPayloadLength {
			b := <-c.workerWrChan
			sndBuf = append(sndBuf, b...)
			wrSz = len(sndBuf)
		}
		if wrSz > maxPayloadLength {
			wrSz = maxPayloadLength
		}

		// Issue a request.
		rdBuf, err := c.roundTrip(sndBuf[:wrSz])
		if err != nil {
			// Welp, something went horrifically wrong.
			break loop
		}

		// Stash the remaining payload if any.
		leftBuf = sndBuf[wrSz:] // Store the remaining data
		if len(leftBuf) == 0 {
			leftBuf = nil
		}

		// Determine the next poll interval.
		if len(rdBuf) > 0 {
			// Received data, enqueue the read.
			c.workerRdChan <- rdBuf

			// And poll immediately.
			interval = 0
		} else if wrSz > 0 {
			// Sent data, poll immediately.
			interval = 0
		} else if interval == 0 {
			// Neither sent nor received data after a poll, re-initialize the delay.
			interval = initPollInterval
		} else {
			// Apply a multiplicative backoff.
			interval = time.Duration(float64(interval) * pollIntervalMultiplier)
			if interval > maxPollInterval {
				interval = maxPollInterval
			}
		}

		runtime.Gosched()
	}

	// Unblock callers waiting in Read() for data that will never arrive,
	// and callers waiting in Write() for data that will never get sent.
	close(c.workerRdChan)
	close(c.workerWrChan)

	// Close the connection (extra calls to Close() are harmless).
	_ = c.Close()
}

func newMeekConn(network, addr string, dialFn base.DialFunc, ca *meekClientArgs) (net.Conn, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}

	var rt http.RoundTripper
	switch ca.utls {
	case nil:
		rt = &http.Transport{Dial: dialFn}
	default:
		rt = newRoundTripper(dialFn, ca.utls, ca.disableHPKP)
	}

	conn := &meekConn{
		args:            ca,
		sessionID:       id,
		roundTripper:    rt,
		workerWrChan:    make(chan []byte, maxChanBacklog),
		workerRdChan:    make(chan []byte, maxChanBacklog),
		workerCloseChan: make(chan struct{}),
	}

	// Start the I/O worker.
	go conn.ioWorker()

	return conn, nil
}

func newSessionID() (string, error) {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	h := sha256.Sum256(b[:])
	return hex.EncodeToString(h[:16]), nil
}

var _ net.Conn = (*meekConn)(nil)
var _ net.Addr = (*meekClientArgs)(nil)
