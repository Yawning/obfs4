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

package main

import (
	"errors"
	"fmt"
	"os"

	"git.torproject.org/pluggable-transports/goptlib"
)

// This file contains things that probably should be in goptlib but are not
// yet or are not finalized.

func ptEnvError(msg string) error {
	line := []byte(fmt.Sprintf("ENV-ERROR %s\n", msg))
	pt.Stdout.Write(line)
	return errors.New(msg)
}

func ptMakeStateDir() (string, error) {
	dir := os.Getenv("TOR_PT_STATE_LOCATION")
	if dir == "" {
		return "", ptEnvError("no TOR_PT_STATE_LOCATION enviornment variable")
	}
	err := os.MkdirAll(dir, 0700)
	return dir, err
}

func ptIsClient() (bool, error) {
	clientEnv := os.Getenv("TOR_PT_CLIENT_TRANSPORTS")
	serverEnv := os.Getenv("TOR_PT_SERVER_TRANSPORTS")
	if clientEnv != "" && serverEnv != "" {
		return false, ptEnvError("TOR_PT_[CLIENT,SERVER]_TRANSPORTS both set")
	} else if clientEnv != "" {
		return true, nil
	} else if serverEnv != "" {
		return false, nil
	}
	return false, errors.New("not launched as a managed transport")
}
