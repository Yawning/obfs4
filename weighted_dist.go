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

package obfs4

import (
	csrand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math/rand"

	"github.com/dchest/siphash"
)

const drbgSeedLength = 32

// drbgSeed is the initial state for a hashDrbg.  It consists of a SipHash-2-4
// key, and 16 bytes of initial data.
type drbgSeed [drbgSeedLength]byte

// bytes returns a pointer to the raw hashDrbg seed.
func (seed *drbgSeed) bytes() *[drbgSeedLength]byte {
	return (*[drbgSeedLength]byte)(seed)
}

// base64 returns the Base64 representation of the seed.
func (seed *drbgSeed) base64() string {
	return base64.StdEncoding.EncodeToString(seed.bytes()[:])
}

// newRandomDrbgSeed returns a drbgSeed initialized with the runtime CSPRNG.
func newRandomDrbgSeed() (seed *drbgSeed, err error) {
	seed = new(drbgSeed)
	_, err = csrand.Read(seed.bytes()[:])
	if err != nil {
		return nil, err
	}

	return
}

// drbgSeedFromBytes returns a drbg seed initialized with the caller provided
// slice.
func drbgSeedFromBytes(src []byte) (seed *drbgSeed, err error) {
	if len(src) != drbgSeedLength {
		return nil, InvalidSeedLengthError(len(src))
	}

	seed = new(drbgSeed)
	copy(seed.bytes()[:], src)

	return
}

/*
func drbgSeedFromBse64(encoded string) (seed *drbgSeed, err error) {
	return
}
*/

// InvalidSeedLengthError is the error returned when the seed provided to the
// DRBG is an invalid length.
type InvalidSeedLengthError int

func (e InvalidSeedLengthError) Error() string {
	return fmt.Sprintf("hashDrbg: Invalid seed length: %d", int(e))
}

// hashDrbg is a CSDRBG based off of SipHash-2-4 in OFB mode.
type hashDrbg struct {
	sip hash.Hash64
	ofb [siphash.Size]byte
}

// newHashDrbg makes a hashDrbg instance based off an optional seed.  The seed
// is truncated to drbgSeedLength.
func newHashDrbg(seed *drbgSeed) *hashDrbg {
	drbg := new(hashDrbg)
	drbg.sip = siphash.New(seed.bytes()[:16])
	copy(drbg.ofb[:], seed.bytes()[16:])

	return drbg
}

// Int63 returns a uniformly distributed random integer [0, 1 << 63).
func (drbg *hashDrbg) Int63() int64 {
	// Use SipHash-2-4 in OFB mode to generate random numbers.
	drbg.sip.Write(drbg.ofb[:])
	copy(drbg.ofb[:], drbg.sip.Sum(nil))

	ret := binary.BigEndian.Uint64(drbg.ofb[:])
	ret &= (1<<63 - 1)

	return int64(ret)
}

// Seed does nothing, call newHashDrbg if you want to reseed.
func (drbg *hashDrbg) Seed(seed int64) {
	// No-op.
}

// wDist is a weighted distribution.
type wDist struct {
	minValue int
	maxValue int
	values   []int
	buckets  []float64
}

// newWDist creates a weighted distribution of values ranging from min to max
// based on a hashDrbg initialized with seed.
func newWDist(seed *drbgSeed, min, max int) (w *wDist) {
	w = new(wDist)
	w.minValue = min
	w.maxValue = max

	if max <= min {
		panic(fmt.Sprintf("wDist.Reset(): min >= max (%d, %d)", min, max))
	}

	w.reset(seed)

	return
}

// sample generates a random value according to the distribution.
func (w *wDist) sample() int {
	retIdx := 0
	totalProb := 0.0
	prob := csRandInstance.Float64()
	for i, bucketProb := range w.buckets {
		totalProb += bucketProb
		if prob <= totalProb {
			retIdx = i
			break
		}
	}

	return w.minValue + w.values[retIdx]
}

// reset generates a new distribution with the same min/max based on a new seed.
func (w *wDist) reset(seed *drbgSeed) {
	// Initialize the deterministic random number generator.
	drbg := newHashDrbg(seed)
	dRng := rand.New(drbg)

	nBuckets := (w.maxValue + 1) - w.minValue
	w.values = dRng.Perm(nBuckets)

	w.buckets = make([]float64, nBuckets)
	var totalProb float64
	for i, _ := range w.buckets {
		prob := dRng.Float64() * (1.0 - totalProb)
		w.buckets[i] = prob
		totalProb += prob
	}
	w.buckets[len(w.buckets)-1] = 1.0
}

/* vim :set ts=4 sw=4 sts=4 noet : */
