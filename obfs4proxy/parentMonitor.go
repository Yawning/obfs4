/*
 * Copyright (c) 2015, Yawning Angel <yawning at torproject dot org>
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
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
)

var parentMonitorOSInit func() error

func initParentMonitor() error {
	// Until #15435 is implemented, there is no reliable way to see if
	// the parent has died that is portable/platform independent/reliable.
	//
	// Do the next best thing and use various kludges and hacks:
	//  * Linux - Platform specific code that should always work.
	//  * Other U*IX - Somewhat generic code, that works unless the parent
	//    dies before the monitor is initialized.
	//  * Windows - Log an error, can't be bothered to figure out how
	//    to handle this there.
	if parentMonitorOSInit != nil {
		return parentMonitorOSInit()
	} else if runtime.GOOS != "windows" {
		ppid := os.Getppid()
		go parentMonitorPpidChange(ppid)
		return nil
	}
	return fmt.Errorf("unsupported on: %s", runtime.GOOS)
}

func parentMonitorPpidChange(ppid int) {
	// Under most if not all U*IX systems, the parent PID will change
	// to that of init once the parent dies.  There are several notable
	// exceptions (Slowlaris/Android), but the parent PID changes
	// under those platforms as well.
	//
	// Naturally we lose if the parent has died by the time when the
	// Getppid() call was issued in our parent, but, this is better
	// than nothing.

	const ppidPollInterval = 1 * time.Second
	for ppid == os.Getppid() {
		time.Sleep(ppidPollInterval)
	}

	// If possible SIGTERM ourself so that the normal shutdown code
	// gets invoked.  If any of that fails, exit anyway, we are a
	// defunt process.
	noticef("Parent pid changed: %d (was %d)", os.Getppid(), ppid)
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		if err := p.Signal(syscall.SIGTERM); err == nil {
			return
		}
		warnf("Failed to SIGTERM ourself: %v", err)
	} else {
		warnf("Failed to find our own process: %v", err)
	}
	os.Exit(-1)
}
