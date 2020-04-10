// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package extra25519

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestElligator(t *testing.T) {
	var publicKey, publicKey2, publicKey3, representative, privateKey [32]byte

	for i := 0; i < 1000; i++ {
		rand.Reader.Read(privateKey[:])

		if !UnsafeBrokenScalarBaseMult(&publicKey, &representative, &privateKey) {
			continue
		}
		UnsafeBrokenRepresentativeToPublicKey(&publicKey2, &representative)
		if !bytes.Equal(publicKey[:], publicKey2[:]) {
			t.Fatal("The resulting public key doesn't match the initial one.")
		}

		curve25519.ScalarBaseMult(&publicKey3, &privateKey)
		if !bytes.Equal(publicKey[:], publicKey3[:]) {
			t.Fatal("The public key doesn't match the value that curve25519 produced.")
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	var publicKey, representative, privateKey [32]byte

	// Find the private key that results in a point that's in the image of the map.
	for {
		rand.Reader.Read(privateKey[:])
		if UnsafeBrokenScalarBaseMult(&publicKey, &representative, &privateKey) {
			break
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		UnsafeBrokenScalarBaseMult(&publicKey, &representative, &privateKey)
	}
}

func BenchmarkMap(b *testing.B) {
	var publicKey, representative [32]byte
	rand.Reader.Read(representative[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		UnsafeBrokenRepresentativeToPublicKey(&publicKey, &representative)
	}
}
