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
	"fmt"
	"math/rand"

	"github.com/yawning/obfs4/csrand"
	"github.com/yawning/obfs4/drbg"
)

const (
	minBuckets = 1
	maxBuckets = 100
)

// wDist is a weighted distribution.
type wDist struct {
	minValue    int
	maxValue    int
	values      []int
	buckets     []int64
	totalWeight int64

	rng *rand.Rand
}

// newWDist creates a weighted distribution of values ranging from min to max
// based on a HashDrbg initialized with seed.
func newWDist(seed *drbg.Seed, min, max int) (w *wDist) {
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
	var totalWeight int64
	weight := csrand.Int63n(w.totalWeight)
	for i, bucketWeight := range w.buckets {
		totalWeight += bucketWeight
		if weight <= totalWeight {
			retIdx = i
			break
		}
	}

	return w.minValue + w.values[retIdx]
}

// reset generates a new distribution with the same min/max based on a new seed.
func (w *wDist) reset(seed *drbg.Seed) {
	// Initialize the deterministic random number generator.
	drbg := drbg.NewHashDrbg(seed)
	w.rng = rand.New(drbg)

	nBuckets := (w.maxValue + 1) - w.minValue
	w.values = w.rng.Perm(nBuckets)
	if nBuckets < minBuckets {
		nBuckets = minBuckets
	}
	if nBuckets > maxBuckets {
		nBuckets = maxBuckets
	}
	nBuckets = w.rng.Intn(nBuckets) + 1

	w.totalWeight = 0
	w.buckets = make([]int64, nBuckets)
	for i, _ := range w.buckets {
		prob := w.rng.Int63n(1000)
		w.buckets[i] = prob
		w.totalWeight += prob
	}
	w.buckets[len(w.buckets)-1] = w.totalWeight
}

/* vim :set ts=4 sw=4 sts=4 noet : */
