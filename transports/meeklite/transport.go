/*
 * Copyright (c) 2019 Yawning Angel <yawning at schwanenlied dot me>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package meeklite

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"gitlab.com/yawning/obfs4.git/transports/base"
)

var (
	errProtocolNegotiated = errors.New("meek_lite: protocol negotiated")

	// This should be kept in sync with what is available in utls.
	clientHelloIDMap = map[string]*utls.ClientHelloID{
		"hellogolang":           nil, // Don't bother with utls.
		"hellorandomized":       &utls.HelloRandomized,
		"hellorandomizedalpn":   &utls.HelloRandomizedALPN,
		"hellorandomizednoalpn": &utls.HelloRandomizedNoALPN,
		"hellofirefox_auto":     &utls.HelloFirefox_Auto,
		"hellofirefox_55":       &utls.HelloFirefox_55,
		"hellofirefox_56":       &utls.HelloFirefox_56,
		"hellofirefox_63":       &utls.HelloFirefox_63,
		"hellochrome_auto":      &utls.HelloChrome_Auto,
		"hellochrome_58":        &utls.HelloChrome_58,
		"hellochrome_62":        &utls.HelloChrome_62,
		"hellochrome_70":        &utls.HelloChrome_70,
		"helloios_auto":         &utls.HelloIOS_Auto,
		"helloios_11_1":         &utls.HelloIOS_11_1,
	}
	defaultClientHello = &utls.HelloChrome_Auto
)

type roundTripper struct {
	sync.Mutex

	clientHelloID *utls.ClientHelloID
	dialFn        base.DialFunc
	transport     http.RoundTripper

	initConn net.Conn
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Note: This isn't protected with a lock, since the meeklite ioWorker
	// serializes RoundTripper requests.
	//
	// This also assumes that req.URL.Host will remain constant for the
	// lifetime of the roundTripper, which is a valid assumption for meeklite.
	if rt.transport == nil {
		if err := rt.getTransport(req); err != nil {
			return nil, err
		}
	}
	return rt.transport.RoundTrip(req)
}

func (rt *roundTripper) getTransport(req *http.Request) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		rt.transport = newHTTPTransport(rt.dialFn, nil)
		return nil
	case "https":
	default:
		return fmt.Errorf("meek_lite: invalid URL scheme: '%v'", req.URL.Scheme)
	}

	_, err := rt.dialTLS("tcp", getDialTLSAddr(req.URL))
	switch err {
	case errProtocolNegotiated:
	case nil:
		// Should never happen.
		panic("meek_lite: dialTLS returned no error when determining transport")
	default:
		return err
	}

	return nil
}

func (rt *roundTripper) dialTLS(network, addr string) (net.Conn, error) {
	// Unlike rt.transport, this is protected by a critical section
	// since past the initial manual call from getTransport, the HTTP
	// client will be the caller.
	rt.Lock()
	defer rt.Unlock()

	// If we have the connection from when we determined the HTTPS
	// transport to use, return that.
	if conn := rt.initConn; conn != nil {
		rt.initConn = nil
		return conn, nil
	}

	rawConn, err := rt.dialFn(network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	conn := utls.UClient(rawConn, &utls.Config{ServerName: host}, *rt.clientHelloID)
	if err = conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	if rt.transport != nil {
		return conn, nil
	}

	// No http.Transport constructed yet, create one based on the results
	// of ALPN.
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// The remote peer is speaking HTTP 2 + TLS.
		rt.transport = &http2.Transport{DialTLS: rt.dialTLSHTTP2}
	default:
		// Assume the remote peer is speaking HTTP 1.x + TLS.
		rt.transport = newHTTPTransport(nil, rt.dialTLS)
	}

	// Stash the connection just established for use servicing the
	// actual request (should be near-immediate).
	rt.initConn = conn

	return nil, errProtocolNegotiated
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return rt.dialTLS(network, addr)
}

func getDialTLSAddr(u *url.URL) string {
	host, port, err := net.SplitHostPort(u.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}

	return net.JoinHostPort(u.Host, u.Scheme)
}

func newRoundTripper(dialFn base.DialFunc, clientHelloID *utls.ClientHelloID) http.RoundTripper {
	return &roundTripper{
		clientHelloID: clientHelloID,
		dialFn:        dialFn,
	}
}

func parseClientHelloID(s string) (*utls.ClientHelloID, error) {
	s = strings.ToLower(s)
	switch s {
	case "none":
		return nil, nil
	case "":
		return defaultClientHello, nil
	default:
		if ret := clientHelloIDMap[s]; ret != nil {
			return ret, nil
		}
	}
	return nil, fmt.Errorf("invalid ClientHelloID: '%v'", s)
}

func newHTTPTransport(dialFn, dialTLSFn base.DialFunc) *http.Transport {
	base := (http.DefaultTransport).(*http.Transport)

	return &http.Transport{
		Dial:    dialFn,
		DialTLS: dialTLSFn,

		// Use default configuration values, taken from the runtime.
		MaxIdleConns:          base.MaxIdleConns,
		IdleConnTimeout:       base.IdleConnTimeout,
		TLSHandshakeTimeout:   base.TLSHandshakeTimeout,
		ExpectContinueTimeout: base.ExpectContinueTimeout,
	}
}

func init() {
	// Attempt to increase compatibility, there's an encrypted link
	// underneath, and this doesn't (shouldn't) affect the external
	// fingerprint.
	utls.EnableWeakCiphers()
}
