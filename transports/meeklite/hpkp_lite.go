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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"time"

	"golang.org/x/net/idna"
)

var builtinPinDB *hpkpDatabase

type hpkpDatabase struct {
	pins map[string]*pinEntry
}

type pinEntry struct {
	digests map[string]bool
	expiry  time.Time
}

func (db *hpkpDatabase) HasPins(host string) (string, bool) {
	h, err := normalizeHost(host)
	if err == nil {
		if entry := db.pins[host]; entry != nil {
			if time.Now().Before(entry.expiry) {
				return h, true
			}
		}
	}
	return h, false
}

func (db *hpkpDatabase) Validate(host string, chains [][]*x509.Certificate) bool {
	host, err := normalizeHost(host)
	if err != nil {
		return false
	}
	entry := db.pins[host]
	if entry == nil {
		return false
	}
	if time.Now().After(entry.expiry) {
		// If the pins are expired, assume that it is valid.
		return true
	}

	// Search for an intersection between the pins and the cert chain.
	for _, chain := range chains {
		for _, cert := range chain {
			derivedPin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			derivedPinEncoded := base64.StdEncoding.EncodeToString(derivedPin[:])
			if entry.digests[derivedPinEncoded] {
				return true
			}
		}
	}

	return false
}

func (db *hpkpDatabase) Add(host string, pins []string, expiry time.Time) {
	h, err := normalizeHost(host)
	if err != nil {
		panic("failed to add hpkp pin, invalid host: " + err.Error())
	}

	pinMap := make(map[string]bool)
	for _, pin := range pins {
		pinMap[pin] = true
	}

	db.pins[h] = &pinEntry{
		digests: pinMap,
		expiry:  expiry,
	}
}

func normalizeHost(host string) (string, error) {
	return idna.Lookup.ToASCII(host)
}

func init() {
	builtinPinDB = &hpkpDatabase{
		pins: make(map[string]*pinEntry),
	}

	// Pin all of Microsoft Azure's root CA certificates for the Tor Browser
	// Azure bridge.
	//
	// See: https://docs.microsoft.com/en-us/azure/security/fundamentals/tls-certificate-changes
	builtinPinDB.Add(
		"ajax.aspnetcdn.com",
		[]string{
			"i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=", // DigiCert Global Root G2 - 2038-01-15 12:00:00
			"r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=", // DigiCert Global Root CA - 2031-11-10 00:00:00
			"Y9mvm0exBk1JoQ57f9Vm28jKo5lFm/woKcVxrYxu80o=", // Baltimore CyberTrust Root - 2025-05-12 23:59:00
			"7KDxgUAs56hlKzG00DbfJH46MLf0GlDZHsT5CwBrQ6E=", // D-TRUST Root Class 3 CA 2 2009 - 2029-11-05 08:35:58
			"svcpi1K/LDysTd/nLeTWgqxYlXWVmC8rYjAa9ZfGmcU=", // Microsoft RSA Root Certificate Authority 2017 - 2042-07-18 23:00:23
			"NfU84SZGEeAzQP434ex9TMmGxWE9ynD9BKpEVF8tryg=", // Microsoft ECC Root Certificate Authority 2017 - 2042-07-18 23:16:04
		},
		// As of 2020-12-07, we're getting the "DigiCert Global Root CA"
		// certificate, so our expiration time matches this certificate.
		time.Date(2031, time.November, 20, 00, 00, 00, 00, time.UTC),
	)
}
