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

	// Pin all of Microsoft's CA intermediary certificates for the
	// Tor Browser Azure bridge.
	//
	// See: https://www.microsoft.com/pki/mscorp/cps/default.htm
	builtinPinDB.Add(
		"ajax.aspnetcdn.com",
		[]string{
			"CzdPous1hY3sIkO55pUH7vklXyIHVZAl/UnprSQvpEI=", // Microsoft IT SSL SHA2 - 2018-05-07 17:03:30
			"xjXxgkOYlag7jCtR5DreZm9b61iaIhd+J3+b2LiybIw=", // Microsoft IT TLS CA 1 - 2024-05-20 12:51:28
			"wBdPad95AU7OgLRs0FU/E6ILO1MSCM84kJ9y0H+TT7s=", // Microsoft IT TLS CA 2 - 2024-05-20 12:51:57
			"wUY9EOTJmS7Aj4fDVCu/KeE++mV7FgIcbn4WhMz1I2k=", // Microsoft IT TLS CA 4 - 2024-05-20 12:52:38
			"RCbqB+W8nwjznTeP4O6VjqcwdxIgI79eBpnBKRr32gc=", // Microsoft IT TLS CA 5 - 2024-05-20 12:53:03
		},
		time.Date(2024, time.May, 20, 00, 00, 00, 00, time.UTC),
	)
}
