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
	"encoding/binary"
	"sync"

	"github.com/dchest/siphash"

	"git.torproject.org/pluggable-transports/obfs4.git/csrand"
)

// maxFilterSize is the maximum capacity of the replay filter.  The busiest
// bridge I know about processes something along the order of 3000 connections
// per day.  The maximum timespan any entry can live in the filter is 2 hours,
// so this value should be sufficient.
const maxFilterSize = 100 * 1024

// replayFilter is a simple filter designed only to answer if it has seen a
// given byte sequence before.  It is based around comparing the SipHash-2-4
// digest of data to match against.  Collisions are treated as positive matches
// however, the probability of such occurences is negligible.
type replayFilter struct {
	lock   sync.Mutex
	key    [2]uint64
	filter map[uint64]*filterEntry
	fifo   *list.List
}

type filterEntry struct {
	firstSeen int64
	hash      uint64
	element   *list.Element
}

// newReplayFilter creates a new replayFilter instance.
func newReplayFilter() (filter *replayFilter, err error) {
	// Initialize the SipHash-2-4 instance with a random key.
	var key [16]byte
	err = csrand.Bytes(key[:])
	if err != nil {
		return
	}

	filter = new(replayFilter)
	filter.key[0] = binary.BigEndian.Uint64(key[0:8])
	filter.key[1] = binary.BigEndian.Uint64(key[8:16])
	filter.filter = make(map[uint64]*filterEntry)
	filter.fifo = list.New()

	return
}

// testAndSet queries the filter for buf, adds it if it was not present and
// returns if it has added the entry or not.  This method is threadsafe.
func (f *replayFilter) testAndSet(now int64, buf []byte) bool {
	hash := siphash.Hash(f.key[0], f.key[1], buf)

	f.lock.Lock()
	defer f.lock.Unlock()

	f.compactFilter(now)

	entry := f.filter[hash]
	if entry != nil {
		return true
	}

	entry = new(filterEntry)
	entry.hash = hash
	entry.firstSeen = now
	entry.element = f.fifo.PushBack(entry)
	f.filter[hash] = entry

	return false
}

// compactFilter purges entries that are too old to be relevant.  If the filter
// is filled to maxFilterCapacity, it will force purge a single entry.  This
// method is NOT threadsafe.
func (f *replayFilter) compactFilter(now int64) {
	e := f.fifo.Front()
	for e != nil {
		entry, _ := e.Value.(*filterEntry)

		// If the filter is at max capacity, force purge at least one entry.
		if f.fifo.Len() < maxFilterSize {
			deltaT := now - entry.firstSeen
			if deltaT < 0 {
				// Aeeeeeee, the system time jumped backwards, potentially by
				// a lot.  This will eventually self-correct, but "eventually"
				// could be a long time.  As much as this sucks, jettison the
				// entire filter.
				f.reset()
				return
			}
			if deltaT < 3600*2 {
				// Why yes, this is 2 hours.  The MAC code includes a hour
				// resolution timestamp, but to deal with clock skew, it
				// accepts time +- 1 hour.
				break
			}
		}
		eNext := e.Next()
		delete(f.filter, entry.hash)
		f.fifo.Remove(entry.element)
		entry.element = nil
		e = eNext
	}
}

// reset purges the entire filter.  This methoid is NOT threadsafe.
func (f *replayFilter) reset() {
	f.filter = make(map[uint64]*filterEntry)
	f.fifo = list.New()
}

/* vim :set ts=4 sw=4 sts=4 noet : */
