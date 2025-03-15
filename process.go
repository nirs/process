/*
Copyright 2025 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package process

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/mitchellh/go-ps"
)

const pidfileMode = 0o600

// WritePidfile writes pid to path.
func WritePidfile(path string, pid int) error {
	data := fmt.Sprintf("%d", pid)
	return os.WriteFile(path, []byte(data), pidfileMode)
}

// ReadPid reads a pid from path.
func ReadPidfile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Pass os.ErrNotExist
		return -1, err
	}
	s := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(s)
	if err != nil {
		return -1, fmt.Errorf("invalid pid %q: %s", s, err)
	}
	return pid, nil
}

// Exists tells if a process with pid and executable name exist. Executable is
// not the path to the executable.
func Exists(pid int, executable string) (bool, error) {
	// Fast path if pid does not exist.
	process, err := os.FindProcess(pid)
	if runtime.GOOS == "windows" {
		// On windows this fails with "OpenProcess: The parameter is incorrect"
		// if the process does not exist.
		if err != nil {
			return false, nil
		}
	} else {
		// On unix this never fails and we get a process in "done" state that
		// returns os.ErrProcessDone from Signal or Wait.
		if err := process.Signal(syscall.Signal(0)); err != nil {
			if err == os.ErrProcessDone {
				return false, nil
			}
		}
	}

	// Slow path if pid exist, depending on the platform:
	// - On windows and darwin this fetch all processes from the krenel and
	//   find a process with pid.
	//   - https://github.com/mitchellh/go-ps/blob/master/process_windows.go
	//   - https://github.com/mitchellh/go-ps/blob/master/process_darwin.go
	// - On linux this reads /proc/pid/stat
	entry, err := ps.FindProcess(pid)
	if err != nil {
		return true, fmt.Errorf("ps.FindProcess(%v): %s", pid, err)
	}
	if entry == nil {
		return false, nil
	}
	return entry.Executable() == executable, nil
}

// Signal sends signal to the process with pid matching name. Returns
// os.ErrProcessDone if the process does not exist, or nil if the signal was
// sent.
func Signal(pid int, executable string, sig syscall.Signal) error {
	exists, err := Exists(pid, executable)
	if err != nil {
		return err
	}
	if !exists {
		return os.ErrProcessDone
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find pid %v: %s", pid, err)
	}
	// Returns os.ErrProcessDone if process does not exist (ESRCH).
	if err := p.Signal(sig); err != nil {
		return fmt.Errorf("failed to send signal %v: %s", sig, err)
	}
	return nil
}

// Terminate kills a process with pid matching executable name. Returns
// os.ErrProcessDone if the process does not exist or nil the kill was
// requested.
func Kill(pid int, executable string) error {
	exists, err := Exists(pid, executable)
	if err != nil {
		return err
	}
	if !exists {
		return os.ErrProcessDone
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find pid %v: %s", pid, err)
	}
	// Returns os.ErrProcessDone if process does not exist (ESRCH).
	if err := p.Kill(); err != nil {
		return fmt.Errorf("failed to kill: %s", err)
	}
	return nil
}
