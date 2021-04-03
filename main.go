// Copyright 2020 Anthony Weems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// sklton-key attaches to arbitrary golang processes and intercepts the
// KeyLogWriter method to enable SSLKEYLOGFILE-style debugging of a target.
//
// KeyLogWriter was introduced in go1.8:
//  https://github.com/golang/go/commit/320bd562cbb24a01beb02706c42d06a290160645
// TLS 1.3 support was added in go1.13
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/go-delve/delve/service"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/debugger"
	"github.com/go-delve/delve/service/rpc2"
	"github.com/go-delve/delve/service/rpccommon"
	"github.com/google/shlex"
)

// Check if an error is an BreakpointExistsError error
func isBreakpointExistsErr(err error) bool {
	return strings.Contains(err.Error(), "Breakpoint exists")
}

// varToBytes converts an api.Variable of type []byte to a []byte
func varToBytes(v api.Variable) []byte {
	out := make([]byte, v.Len)
	for i := range out {
		v, _ := strconv.Atoi(v.Children[i].Value)
		out[i] = byte(v)
	}
	return out
}

// SSL added and removed here ;-)
// Handle two possible type signatures:
//  func (c *Config) writeKeyLog(clientRandom, masterSecret []byte) error
//  func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error
func writeKeyLog(w io.Writer, args []api.Variable) {
	var label string
	var clientRandom, secret []byte

	// In delve v1.5.0, the end of the args array contains the return type and
	// the receiver if present. The writeKeyLog method has a receiver and returns
	// a single value, therefore, the argument array length is len+2.
	if len(args) == 4 {
		label = "CLIENT_RANDOM"
	} else if len(args) == 5 {
		label, args = args[0].Value, args[1:]
	} else {
		log.Fatalf("unknown type signature with %d args", len(args))
	}

	clientRandom = varToBytes(args[0])
	args = args[1:]

	secret = varToBytes(args[0])
	args = args[1:]

	fmt.Fprintf(w, "%s %x %x\n", label, clientRandom, secret)
}

var (
	flagAttachPid int
	flagExecCmd   string

	flagTcpdump    bool
	flagDeviceName string

	flagLogFilename  string
	flagPcapFilename string
)

func main() {
	// debugger flags
	flag.IntVar(&flagAttachPid, "pid", 0, "Pid to attach to.")
	flag.StringVar(&flagExecCmd, "cmd", "", "Command to launch and attach to.")

	// packet capture flags
	flag.BoolVar(&flagTcpdump, "tcpdump", false, "If true, capture packets and save pcap to a file")
	flag.StringVar(&flagDeviceName, "dev", "eth0", "Device to capture packets on")

	// output flags
	flag.StringVar(&flagPcapFilename, "pcap", "skl.pcap", "Path to write pcap to")
	flag.StringVar(&flagLogFilename, "log", "skl.log", "Log file to write key log to")

	flag.Parse()

	// Set up log file io.Writer
	var err error
	var w io.WriteCloser
	if flagLogFilename != "" && flagLogFilename != "-" {
		log.Printf("writing secrets to %s", flagLogFilename)
		w, err = os.OpenFile(flagLogFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		w = os.Stdout
	}
	defer w.Close()

	// Capture packet trace and save to file
	if flagTcpdump {
		go PacketCapture(flagPcapFilename, flagDeviceName)
	}

	// Make a local in-memory connection that client and server use to communicate
	listener, clientConn := service.ListenerPipe()
	defer listener.Close()

	pid := flagAttachPid
	if flagExecCmd != "" {
		args, err := shlex.Split(flagExecCmd)
		if err != nil {
			log.Fatalf("error splitting cmd: %s", err)
		}
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Fatal(err)
		}
		pid = cmd.Process.Pid
	}

	// Create and start a debug server
	server := rpccommon.NewServer(&service.Config{
		Listener:   listener,
		APIVersion: 2,
		Debugger: debugger.Config{
			AttachPid:      pid,
			Backend:        "default",
			CheckGoVersion: true,
		},
	})
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}

	// Attach client to server
	client := rpc2.NewClientFromConn(clientConn)
	defer client.Detach(false)

	// Search for writeKeyLog function and set breakpoint
	locs, err := client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: 0},
		"crypto/tls.(*Config).writeKeyLog", true)
	if err != nil {
		log.Fatal(err)
	}
	for i := range locs {
		_, err = client.CreateBreakpoint(&api.Breakpoint{Addr: locs[i].PC})
		if err != nil && !isBreakpointExistsErr(err) {
			log.Fatal(err)
		}
		log.Printf("hooked %s at %s:%d", locs[i].Function.Name(), locs[i].File, locs[i].Line)
	}

	// Run the program, print key log on each breakpoint
	for {
		st := <-client.Continue()
		if st.Exited {
			log.Printf("process exited with status %d", st.ExitStatus)
			break
		}
		args, err := client.ListFunctionArgs(api.EvalScope{
			GoroutineID: st.SelectedGoroutine.ID,
			Frame:       0,
		}, api.LoadConfig{
			MaxStringLen:   256,
			MaxArrayValues: 256,
		})
		if err != nil {
			log.Fatalf("error listing args: %s", err)
		}

		writeKeyLog(w, args)
	}
}
