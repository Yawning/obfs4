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

	"golang.org/x/net/idna"
)

var builtinPinDB *hpkpDatabase

type hpkpDatabase struct {
	pins map[string]map[string]bool
}

func (db *hpkpDatabase) HasPins(host string) (string, bool) {
	h, err := normalizeHost(host)
	return h, (db.pins[host] != nil && err == nil)
}

func (db *hpkpDatabase) Validate(host string, chains [][]*x509.Certificate) bool {
	var ok bool
	if host, ok = db.HasPins(host); !ok {
		return false
	}

	pins := db.pins[host]
	for _, chain := range chains {
		for _, cert := range chain {
			derivedPin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			derivedPinEncoded := base64.StdEncoding.EncodeToString(derivedPin[:])
			if !pins[derivedPinEncoded] {
				return false
			}
		}
	}

	return true
}

func (db *hpkpDatabase) Add(host string, pins []string) {
	h, err := normalizeHost(host)
	if err != nil {
		panic("failed to add hpkp pin, invalid host: " + err.Error())
	}

	pinMap := make(map[string]bool)
	for _, pin := range pins {
		pinMap[pin] = true
	}

	db.pins[h] = pinMap
}

func normalizeHost(host string) (string, error) {
	return idna.Lookup.ToASCII(host)
}

func init() {
	builtinPinDB = &hpkpDatabase{
		pins: make(map[string]map[string]bool),
	}

	// Generated on 2019-02-04.
	builtinPinDB.Add("ajax.aspnetcdn.com", []string{
		"PPjoAKk+kCVr9VNPXJkyHXEKnIyd5t5NqpPL3zCvJOE=",
		"wBdPad95AU7OgLRs0FU/E6ILO1MSCM84kJ9y0H+TT7s=",
		"Y9mvm0exBk1JoQ57f9Vm28jKo5lFm/woKcVxrYxu80o=",
	})
}
