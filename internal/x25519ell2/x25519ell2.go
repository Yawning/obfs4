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

// Package x25519ell2 implements obfuscated X25519 ECDH, via the Elligator2
// mapping.
package x25519ell2 // import "gitlab.com/yawning/obfs4.git/internal/x25519ell2"

import (
	"encoding/binary"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"gitlab.com/yawning/edwards25519-extra/elligator2"
)

// The corrected version of this that solves the implementation errors
// present in the historical implementation by agl is derived from
// Monocypher (CC-0 or BSD-2) by Loup Vaillant.  Without their efforts
// and prodding, this would likely have stayed broken forever.

var (
	feOne = new(field.Element).One()

	feNegTwo = mustFeFromBytes([]byte{
		0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	})

	feA = mustFeFromUint64(486662)

	feSqrtM1 = mustFeFromBytes([]byte{
		0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
		0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
	})

	// Low order point Edwards x-coordinate `sqrt((sqrt(d + 1) + 1) / d)`.
	feLopX = mustFeFromBytes([]byte{
		0x4a, 0xd1, 0x45, 0xc5, 0x46, 0x46, 0xa1, 0xde, 0x38, 0xe2, 0xe5, 0x13, 0x70, 0x3c, 0x19, 0x5c,
		0xbb, 0x4a, 0xde, 0x38, 0x32, 0x99, 0x33, 0xe9, 0x28, 0x4a, 0x39, 0x06, 0xa0, 0xb9, 0xd5, 0x1f,
	})

	// Low order point Edwards y-coordinate `-lop_x * sqrtm1`.
	feLopY = mustFeFromBytes([]byte{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	})
)

func mustFeFromBytes(b []byte) *field.Element {
	fe, err := new(field.Element).SetBytes(b)
	if err != nil {
		panic("internal/x25519ell2: failed to deserialize constant: " + err.Error())
	}
	return fe
}

func mustFeFromUint64(x uint64) *field.Element {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:], x)
	return mustFeFromBytes(b[:])
}

func selectLowOrderPoint(out, x, k *field.Element, cofactor uint8) {
	out.Zero()
	out.Select(k, out, int((cofactor>>1)&1)) // bit 1
	out.Select(x, out, int((cofactor>>0)&1)) // bit 0
	var tmp field.Element
	tmp.Negate(out)
	out.Select(&tmp, out, int((cofactor>>2)&1)) // bit 2
}

func scalarBaseMultDirty(privateKey *[32]byte) *field.Element {
	// Compute clean scalar multiplication
	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(privateKey[:])
	if err != nil {
		panic("internal/x25519ell2: failed to deserialize scalar: " + err.Error())
	}
	pk := new(edwards25519.Point).ScalarBaseMult(scalar)

	// Compute low order point
	var lopX, lopY, lopT field.Element
	selectLowOrderPoint(&lopX, feLopX, feSqrtM1, privateKey[0])
	selectLowOrderPoint(&lopY, feLopY, feOne, privateKey[0]+2)
	// Z = one
	lopT.Multiply(&lopX, &lopY)
	lop, err := new(edwards25519.Point).SetExtendedCoordinates(&lopX, &lopY, feOne, &lopT)
	if err != nil {
		panic("interal/x25519ell2: failed to create edwards point from x, y: " + err.Error())
	}

	// Add low order point to the public key
	pk.Add(pk, lop)

	// Convert to Montgomery u coordinate (we ignore the sign)
	_, yExt, zExt, _ := pk.ExtendedCoordinates()
	var t1, t2 field.Element
	t1.Add(zExt, yExt)
	t2.Subtract(zExt, yExt)
	t2.Invert(&t2)
	t1.Multiply(&t1, &t2)

	return &t1
}

func uToRepresentative(representative *[32]byte, u *field.Element, tweak byte) bool {
	t1 := new(field.Element).Set(u)

	t2 := new(field.Element).Add(t1, feA)
	t3 := new(field.Element).Multiply(t1, t2)
	t3.Multiply(t3, feNegTwo)
	if _, isSquare := t3.SqrtRatio(feOne, t3); isSquare == 1 {
		t1.Select(t2, t1, int(tweak&1))
		t3.Multiply(t1, t3)
		t1.Mult32(t3, 2)
		t2.Negate(t3)
		tmp := t1.Bytes()
		t3.Select(t2, t3, int(tmp[0]&1))
		copy(representative[:], t3.Bytes())

		// Pad with two random bits
		representative[31] |= tweak & 0xc0

		return true
	}

	return false
}

// ScalarBaseMult computes a curve25519 public key from a private
// key and also a uniform representative for that public key.
// Note that this function will fail and return false for about
// half of private keys.
//
// The `privateKey` input MUST be the full 32-bytes of entropy
// (X25519-style "clamping" will result in non-uniformly distributed
// representatives).
//
// WARNING: The underlying scalar multiply explicitly does not clear
// the cofactor, and thus the public keys will be different from
// those produced by normal implementations.
func ScalarBaseMult(publicKey, representative, privateKey *[32]byte, tweak byte) bool {
	u := scalarBaseMultDirty(privateKey)
	if !uToRepresentative(representative, u, tweak) {
		// No representative.
		return false
	}
	copy(publicKey[:], u.Bytes())
	return true
}

// RepresentativeToPublicKey converts a uniform representative value for
// a curve25519 public key, as produced by ScalarBaseMult, to a curve25519
// public key.
func RepresentativeToPublicKey(publicKey, representative *[32]byte) {
	// Representatives are encoded in 254 bits.
	var clamped [32]byte
	copy(clamped[:], representative[:])
	clamped[31] &= 63

	var fe field.Element
	if _, err := fe.SetBytes(clamped[:]); err != nil {
		// Panic is fine, the only way this fails is if the representative
		// is not 32-bytes.
		panic("internal/x25519ell2: failed to deserialize representative: " + err.Error())
	}
	u, _ := elligator2.MontgomeryFlavor(&fe)
	copy(publicKey[:], u.Bytes())
}
