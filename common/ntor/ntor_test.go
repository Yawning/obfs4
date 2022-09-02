/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
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

package ntor

import (
	"bytes"
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"gitlab.com/yawning/edwards25519-extra.git/elligator2"
)

// TestNewKeypair tests Curve25519/Elligator keypair generation.
func TestNewKeypair(t *testing.T) {
	// Test standard Curve25519 first.
	keypair, err := NewKeypair(false)
	if err != nil {
		t.Fatal("NewKeypair(false) failed:", err)
	}
	if keypair == nil {
		t.Fatal("NewKeypair(false) returned nil")
	}
	if keypair.HasElligator() {
		t.Fatal("NewKeypair(false) has a Elligator representative")
	}

	// Test Elligator generation.
	keypair, err = NewKeypair(true)
	if err != nil {
		t.Fatal("NewKeypair(true) failed:", err)
	}
	if keypair == nil {
		t.Fatal("NewKeypair(true) returned nil")
	}
	if !keypair.HasElligator() {
		t.Fatal("NewKeypair(true) mising an Elligator representative")
	}
}

// Test Client/Server handshake.
func TestHandshake(t *testing.T) {
	clientKeypair, err := NewKeypair(true)
	if err != nil {
		t.Fatal("Failed to generate client keypair:", err)
	}
	if clientKeypair == nil {
		t.Fatal("Client keypair is nil")
	}

	serverKeypair, err := NewKeypair(true)
	if err != nil {
		t.Fatal("Failed to generate server keypair:", err)
	}
	if serverKeypair == nil {
		t.Fatal("Server keypair is nil")
	}

	idKeypair, err := NewKeypair(false)
	if err != nil {
		t.Fatal("Failed to generate identity keypair:", err)
	}
	if idKeypair == nil {
		t.Fatal("Identity keypair is nil")
	}

	nodeID, err := NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	if err != nil {
		t.Fatal("Failed to load NodeId:", err)
	}

	// ServerHandshake
	clientPublic := clientKeypair.Representative().ToPublic()
	ok, serverSeed, serverAuth := ServerHandshake(clientPublic,
		serverKeypair, idKeypair, nodeID)
	if !ok {
		t.Fatal("ServerHandshake failed")
	}
	if serverSeed == nil {
		t.Fatal("ServerHandshake returned nil KEY_SEED")
	}
	if serverAuth == nil {
		t.Fatal("ServerHandshake returned nil AUTH")
	}

	// ClientHandshake
	ok, clientSeed, clientAuth := ClientHandshake(clientKeypair,
		serverKeypair.Public(), idKeypair.Public(), nodeID)
	if !ok {
		t.Fatal("ClientHandshake failed")
	}
	if clientSeed == nil {
		t.Fatal("ClientHandshake returned nil KEY_SEED")
	}
	if clientAuth == nil {
		t.Fatal("ClientHandshake returned nil AUTH")
	}

	// WARNING: Use a constant time comparison in actual code.
	if 0 != bytes.Compare(clientSeed.Bytes()[:], serverSeed.Bytes()[:]) {
		t.Fatal("KEY_SEED mismatched between client/server")
	}
	if 0 != bytes.Compare(clientAuth.Bytes()[:], serverAuth.Bytes()[:]) {
		t.Fatal("AUTH mismatched between client/server")
	}
}

// TestPublicKeySubgroup tests that Elligator representatives produced by
// NewKeypair map to public keys that are not always on the prime-order subgroup
// of Curve25519. (And incidentally that Elligator representatives agree with
// the public key stored in the Keypair.)
//
// See discussion under "Step 2" at https://elligator.org/key-exchange.
func TestPublicKeySubgroup(t *testing.T) {
	// We will test the public keys that comes out of NewKeypair by
	// multiplying each one by L, the order of the prime-order subgroup of
	// Curve25519, then checking the order of the resulting point. The error
	// condition we are checking for specifically is output points always
	// having order 1, which means that public keys are always on the
	// prime-order subgroup of Curve25519, which would make Elligator
	// representatives distinguishable from random. More generally, we want
	// to ensure that all possible output points of low order are covered.
	//
	// We have to do some contortions to conform to the interfaces we use.
	// We do scalar multiplication by L using Edwards coordinates, rather
	// than the Montgomery coordinates output by Keypair.Public and
	// Representative.ToPublic, because the Montgomery-based
	// crypto/curve25519.X25519 clamps the scalar to be a multiple of 8,
	// which would not allow us to use the scalar we need. The Edwards-based
	// ScalarMult only accepts scalars that are strictly less than L; we
	// work around this by multiplying the point by L - 1, then adding the
	// point once to the product.

	scalarOrderMinus1, err := edwards25519.NewScalar().SetCanonicalBytes(
		// This is the same as scMinusOne in filippo.io/edwards25519.
		// https://github.com/FiloSottile/edwards25519/blob/v1.0.0/scalar.go#L34
		[]byte{236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16},
	)
	if err != nil {
		panic(err)
	}
	// Returns a new edwards25519.Point that is v multiplied by the subgroup
	// order.
	scalarMultOrder := func(v *edwards25519.Point) *edwards25519.Point {
		p := new(edwards25519.Point)
		// v * (L - 1) + v => v * L
		p.ScalarMult(scalarOrderMinus1, v)
		p.Add(p, v)
		return p
	}

	// Generates a new Keypair using NewKeypair, and returns the Keypair
	// along, with its public key as a newly allocated edwards25519.Point.
	generate := func() (*Keypair, *edwards25519.Point) {
		kp, err := NewKeypair(true)
		if err != nil {
			panic(err)
		}

		// We will be using the Edwards representation of the public key
		// (mapped from the Elligator representative) for further
		// processing. But while we're here, check that the Montgomery
		// representation output by Representative agrees with the
		// stored public key.
		if *kp.Representative().ToPublic() != *kp.Public() {
			t.Fatal(kp.Representative().ToPublic(), kp.Public())
		}

		// Do the Elligator map in Edwards coordinates.
		var clamped [32]byte
		copy(clamped[:], kp.Representative().Bytes()[:])
		clamped[31] &= 63
		repr, err := new(field.Element).SetBytes(clamped[:])
		if err != nil {
			panic(err)
		}
		ed := elligator2.EdwardsFlavor(repr)
		if !bytes.Equal(ed.BytesMontgomery(), kp.Public().Bytes()[:]) {
			panic("Failed to derive an equivalent public key in Edwards coordinates")
		}
		return kp, ed
	}

	// These are all the points of low order that may result from
	// multiplying an Elligator-mapped point by L. We will test that all of
	// them are covered.
	lowOrderPoints := [][32]byte{
		/* order 1 */ {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		/* order 2 */ {236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		/* order 4 */ {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		/* order 4 */ {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128},
		/* order 8 */ {38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5},
		/* order 8 */ {38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 133},
		/* order 8 */ {199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122},
		/* order 8 */ {199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 250},
	}
	counts := make(map[[32]byte]int)
	for _, b := range lowOrderPoints {
		counts[b] = 0
	}
	// Assuming a uniform distribution of representatives, the probability
	// that a specific low-order point will not be covered after n trials is
	// (7/8)^n. The probability that *any* of the 8 low-order points will
	// remain uncovered after n trials is at most 8 times that, 8*(7/8)^n.
	// We must do at least log((1e-12)/8)/log(7/8) = 222.50 trials, in the
	// worst case, to ensure a false error rate of less than 1 in a
	// trillion. In practice, we keep track of the number of covered points
	// and break the loop when it reaches 8, so when representatives are
	// actually uniform we will usually run much fewer iterations.
	numCovered := 0
	for i := 0; i < 225; i++ {
		kp, pk := generate()
		v := scalarMultOrder(pk)
		var b [32]byte
		copy(b[:], v.Bytes())
		if _, ok := counts[b]; !ok {
			t.Fatalf("map(%x)*order yielded unexpected point %v",
				*kp.Representative().Bytes(), b)
		}
		counts[b]++
		if counts[b] == 1 {
			// We just covered a new point for the first time.
			numCovered++
			if numCovered == len(lowOrderPoints) {
				break
			}
		}
	}
	for _, b := range lowOrderPoints {
		count, ok := counts[b]
		if !ok {
			panic(b)
		}
		if count == 0 {
			t.Errorf("low-order point %x not covered", b)
		}
	}
}

// Benchmark Client/Server handshake.  The actual time taken that will be
// observed on either the Client or Server is half the reported time per
// operation since the benchmark does both sides.
func BenchmarkHandshake(b *testing.B) {
	// Generate the "long lasting" identity key and NodeId.
	idKeypair, err := NewKeypair(false)
	if err != nil || idKeypair == nil {
		b.Fatal("Failed to generate identity keypair")
	}
	nodeID, err := NewNodeID([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"))
	if err != nil {
		b.Fatal("Failed to load NodeId:", err)
	}
	b.ResetTimer()

	// Start the actual benchmark.
	for i := 0; i < b.N; i++ {
		// Generate the keypairs.
		serverKeypair, err := NewKeypair(true)
		if err != nil || serverKeypair == nil {
			b.Fatal("Failed to generate server keypair")
		}

		clientKeypair, err := NewKeypair(true)
		if err != nil || clientKeypair == nil {
			b.Fatal("Failed to generate client keypair")
		}

		// Server handshake.
		clientPublic := clientKeypair.Representative().ToPublic()
		ok, serverSeed, serverAuth := ServerHandshake(clientPublic,
			serverKeypair, idKeypair, nodeID)
		if !ok || serverSeed == nil || serverAuth == nil {
			b.Fatal("ServerHandshake failed")
		}

		// Client handshake.
		serverPublic := serverKeypair.Representative().ToPublic()
		ok, clientSeed, clientAuth := ClientHandshake(clientKeypair,
			serverPublic, idKeypair.Public(), nodeID)
		if !ok || clientSeed == nil || clientAuth == nil {
			b.Fatal("ClientHandshake failed")
		}

		// Validate the authenticator.  Real code would pass the AUTH read off
		// the network as a slice to CompareAuth here.
		if !CompareAuth(clientAuth, serverAuth.Bytes()[:]) ||
			!CompareAuth(serverAuth, clientAuth.Bytes()[:]) {
			b.Fatal("AUTH mismatched between client/server")
		}
	}
}
