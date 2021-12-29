// Copyright (c) 2021 Yawning Angel <yawning at schwanenlied dot me>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package x25519ell2

import (
	"bytes"
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/curve25519"
)

func TestX25519Ell2(t *testing.T) {
	t.Run("Constants", testConstants)
	t.Run("KeyExchage", testKeyExchange)
}

func testConstants(t *testing.T) {
	// While the constants were calculated and serialized with a known
	// correct implementation of the field arithmetic, re-derive them
	// to be sure.

	t.Run("NegTwo", func(t *testing.T) {
		expected := new(field.Element).Add(feOne, feOne)
		expected.Negate(expected)

		if expected.Equal(feNegTwo) != 1 {
			t.Fatalf("invalid value for -2: %x", feNegTwo.Bytes())
		}
	})

	t.Run("LopX", func(t *testing.T) {
		// d = -121665/121666
		d := mustFeFromUint64(121666)
		d.Invert(d)
		d.Multiply(d, mustFeFromUint64(121665))
		d.Negate(d)

		// lop_x = sqrt((sqrt(d + 1) + 1) / d)
		expected := new(field.Element).Add(d, feOne)
		expected.Invert(expected)
		expected.SqrtRatio(feOne, expected)
		expected.Add(expected, feOne)
		expected.SqrtRatio(expected, d)

		if expected.Equal(feLopX) != 1 {
			t.Fatalf("invalid value for low order point X: %x", feLopX.Bytes())
		}
	})

	t.Run("LopY", func(t *testing.T) {
		// lop_y = -lop_x * sqrtm1
		expected := new(field.Element).Negate(feLopX)
		expected.Multiply(expected, feSqrtM1)

		if expected.Equal(feLopY) != 1 {
			t.Fatalf("invalid value for low order point Y: %x", feLopY.Bytes())
		}
	})
}

func testKeyExchange(t *testing.T) {
	var randSk [32]byte
	_, _ = rand.Read(randSk[:])

	var good, bad int
	for i := 0; i < 1000; i++ {
		var (
			publicKey, privateKey, representative [32]byte
			publicKeyClean                        [32]byte
			tweak                                 [1]byte
		)
		_, _ = rand.Read(privateKey[:])
		_, _ = rand.Read(tweak[:])

		// This won't match the public key from the Elligator2-ed scalar
		// basepoint multiply, but we want to ensure that the public keys
		// we do happen to generate are interoperable (otherwise something
		// is badly broken).
		curve25519.ScalarBaseMult(&publicKeyClean, &privateKey)

		if !ScalarBaseMult(&publicKey, &representative, &privateKey, tweak[0]) {
			t.Logf("bad: %x", privateKey)
			bad++
			continue
		}
		t.Logf("good: %x", privateKey)

		t.Logf("publicKey: %x, repr: %x", publicKey, representative)

		var shared, sharedRep, sharedClean, pkFromRep [32]byte
		RepresentativeToPublicKey(&pkFromRep, &representative)
		if !bytes.Equal(pkFromRep[:], publicKey[:]) {
			t.Fatalf("public key mismatch(repr): expected %x, actual: %x", publicKey, pkFromRep)
		}

		curve25519.ScalarMult(&sharedClean, &randSk, &publicKeyClean) //nolint: staticcheck
		curve25519.ScalarMult(&shared, &randSk, &publicKey)           //nolint: staticcheck
		curve25519.ScalarMult(&sharedRep, &randSk, &pkFromRep)        //nolint: staticcheck

		if !bytes.Equal(shared[:], sharedRep[:]) {
			t.Fatalf("shared secret mismatch: expected %x, actual: %x", shared, sharedRep)
		}
		if !bytes.Equal(shared[:], sharedClean[:]) {
			t.Fatalf("shared secret mismatch(clean): expected %x, actual: %x", shared, sharedClean)
		}

		good++
	}

	t.Logf("good: %d, bad: %d", good, bad)
}

func BenchmarkKeyGeneration(b *testing.B) {
	var publicKey, representative, privateKey [32]byte

	// Find the private key that results in a point that's in the image of the map.
	for {
		_, _ = rand.Reader.Read(privateKey[:])
		if ScalarBaseMult(&publicKey, &representative, &privateKey, 0) {
			break
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScalarBaseMult(&publicKey, &representative, &privateKey, 0)
	}
}

func BenchmarkMap(b *testing.B) {
	var publicKey, representative [32]byte
	_, _ = rand.Reader.Read(representative[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RepresentativeToPublicKey(&publicKey, &representative)
	}
}
