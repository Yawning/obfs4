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
	"container/list"
	"fmt"
	"math/rand"

	"github.com/yawning/obfs4/csrand"
	"github.com/yawning/obfs4/drbg"
)

const (
	minValues = 1
	maxValues = 100
)

// wDist is a weighted distribution.
type wDist struct {
	minValue int
	maxValue int
	values   []int
	weights  []float64

	alias []int
	prob  []float64
}

// newWDist creates a weighted distribution of values ranging from min to max
// based on a HashDrbg initialized with seed.
func newWDist(seed *drbg.Seed, min, max int) (w *wDist) {
	w = &wDist{minValue: min, maxValue: max}

	if max <= min {
		panic(fmt.Sprintf("wDist.Reset(): min >= max (%d, %d)", min, max))
	}

	w.reset(seed)

	return
}

// genValues creates a slice containing a random number of random values
// that when scaled by adding minValue will fall into [min, max].
func (w *wDist) genValues(rng *rand.Rand) {
	nValues := (w.maxValue + 1) - w.minValue
	values := rng.Perm(nValues)
	if nValues < minValues {
		nValues = minValues
	}
	if nValues > maxValues {
		nValues = maxValues
	}
	nValues = rng.Intn(nValues) + 1
	w.values = values[:nValues]
}

// genBiasedWeights generates a non-uniform weight list, similar to the
// ScrambleSuit prob_dist module.
func (w *wDist) genBiasedWeights(rng *rand.Rand) {
	w.weights = make([]float64, len(w.values))

	culmProb := 0.0
	for i := range w.values {
		p := (1.0 - culmProb) * rng.Float64()
		w.weights[i] = p
		culmProb += p
	}
}

// genUniformWeights generates a uniform weight list.
func (w *wDist) genUniformWeights(rng *rand.Rand) {
	w.weights = make([]float64, len(w.values))
	for i := range w.weights {
		w.weights[i] = rng.Float64()
	}
}

// genTables calculates the alias and prob tables used for Vose's Alias method.
// Algorithm taken from http://www.keithschwarz.com/darts-dice-coins/
func (w *wDist) genTables() {
	n := len(w.weights)
	var sum float64
	for _, weight := range w.weights {
		sum += weight
	}

	// Create arrays $Alias$ and $Prob$, each of size $n$.
	alias := make([]int, n)
	prob := make([]float64, n)

	// Create two worklists, $Small$ and $Large$.
	small := list.New()
	large := list.New()

	scaled := make([]float64, n)
	for i, weight := range w.weights {
		// Multiply each probability by $n$.
		p_i := weight * float64(n) / sum
		scaled[i] = p_i

		// For each scaled probability $p_i$:
		if scaled[i] < 1.0 {
			// If $p_i < 1$, add $i$ to $Small$.
			small.PushBack(i)
		} else {
			// Otherwise ($p_i \ge 1$), add $i$ to $Large$.
			large.PushBack(i)
		}
	}

	// While $Small$ and $Large$ are not empty: ($Large$ might be emptied first)
	for small.Len() > 0 && large.Len() > 0 {
		// Remove the first element from $Small$; call it $l$.
		l := small.Remove(small.Front()).(int)
		// Remove the first element from $Large$; call it $g$.
		g := large.Remove(large.Front()).(int)

		// Set $Prob[l] = p_l$.
		prob[l] = scaled[l]
		// Set $Alias[l] = g$.
		alias[l] = g

		// Set $p_g := (p_g + p_l) - 1$. (This is a more numerically stable option.)
		scaled[g] = (scaled[g] + scaled[l]) - 1.0

		if scaled[g] < 1.0 {
			// If $p_g < 1$, add $g$ to $Small$.
			small.PushBack(g)
		} else {
			// Otherwise ($p_g \ge 1$), add $g$ to $Large$.
			large.PushBack(g)
		}
	}

	// While $Large$ is not empty:
	for large.Len() > 0 {
		// Remove the first element from $Large$; call it $g$.
		g := large.Remove(large.Front()).(int)
		// Set $Prob[g] = 1$.
		prob[g] = 1.0
	}

	// While $Small$ is not empty: This is only possible due to numerical instability.
	for small.Len() > 0 {
		// Remove the first element from $Small$; call it $l$.
		l := small.Remove(small.Front()).(int)
		// Set $Prob[l] = 1$.
		prob[l] = 1.0
	}

	w.prob = prob
	w.alias = alias
}

// reset generates a new distribution with the same min/max based on a new seed.
func (w *wDist) reset(seed *drbg.Seed) {
	// Initialize the deterministic random number generator.
	drbg := drbg.NewHashDrbg(seed)
	rng := rand.New(drbg)

	w.genValues(rng)
	//w.genBiasedWeights(rng)
	w.genUniformWeights(rng)
	w.genTables()
}

// sample generates a random value according to the distribution.
func (w *wDist) sample() int {
	var idx int

	// Generate a fair die roll from an $n$-sided die; call the side $i$.
	i := csrand.Intn(len(w.values))
	// Flip a biased coin that comes up heads with probability $Prob[i]$.
	if csrand.Float64() <= w.prob[i] {
		// If the coin comes up "heads," return $i$.
		idx = i
	} else {
		// Otherwise, return $Alias[i]$.
		idx = w.alias[i]
	}

	return w.minValue + w.values[idx]
}

/* vim :set ts=4 sw=4 sts=4 noet : */
