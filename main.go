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
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-delve/delve/service"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/debugger"
	"github.com/go-delve/delve/service/rpc2"
	"github.com/go-delve/delve/service/rpccommon"
	"github.com/google/shlex"
)

// pidof searches /proc for a process matching name
// search continues until process exists or timeout expires
func pidof(name string) (int, error) {
	log.Printf("searching for pidof %s", name)

	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-timeout:
			return 0, fmt.Errorf("timeout")
		default:
			pid, err := PidOf(name)
			if err != nil {
				return 0, err
			}
			if pid > 0 {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("unreachable")
}

// Check if an error is an BreakpointExistsError error
func isBreakpointExistsErr(err error) bool {
	return strings.Contains(err.Error(), "Breakpoint exists")
}

// varToBytes converts an api.Variable of type []byte to a []byte
func varToBytes(v api.Variable) []byte {
	var size int64
	if v.Len < v.Cap {
		size = v.Len
	} else {
		size = v.Cap
	}
	out := make([]byte, size)
	for i := range out {
		v, _ := strconv.Atoi(v.Children[i].Value)
		out[i] = byte(v)
	}
	return out
}

func lookup(v api.Variable, name string) api.Variable {
	parts := strings.Split(name, ".")
	for _, part := range parts {
		if v.Kind == reflect.Ptr && len(v.Children) == 1 {
			v = v.Children[0]
		}
		var found bool
		for _, child := range v.Children {
			if child.Name == part {
				v = child
				found = true
			}
		}
		if !found {
			log.Printf("failed to find child %s", name)
			return api.Variable{}
		}
	}
	return v
}

type keyLogWriter struct {
	w io.Writer
}

func NewKeyLogWriter(w io.Writer) *keyLogWriter {
	return &keyLogWriter{
		w: w,
	}
}

const (
	keyLogLabelTLS12           = "CLIENT_RANDOM"
	keyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
)

// SSL added and removed here ;-)
// Handle two possible type signatures:
//  func (c *Config) writeKeyLog(clientRandom, masterSecret []byte) error
//  func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error
func (klw *keyLogWriter) WriteKeyLog(stack []api.Stackframe, args []api.Variable) {
	var clientRandom, secret, serverSecret, clientSecret []byte

	if len(stack) < 2 {
		log.Printf("unknown stack with %d entries", len(stack))
		return
	}
	if len(args) < 1 {
		log.Printf("unknown type signature with %d args", len(args))
		return
	}

	frame := stack[1]
	fname := frame.Location.Function.Name()

	rcvr := args[0]
	switch rcvr.Type {
	case "*crypto/tls.clientHandshakeState":
		switch fname {
		case "crypto/tls.(*clientHandshakeState).doFullHandshake":
			clientRandom = varToBytes(lookup(rcvr, "hello.random"))
			secret = varToBytes(lookup(rcvr, "masterSecret"))
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelTLS12, clientRandom, secret)
		default:
			log.Printf("unknown function %s", fname)
			return
		}

	case "*crypto/tls.serverHandshakeState":
		switch fname {
		case "crypto/tls.(*serverHandshakeState).doFullHandshake":
			clientRandom = varToBytes(lookup(rcvr, "clientHello.random"))
			secret = varToBytes(lookup(rcvr, "masterSecret"))
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelTLS12, clientRandom, secret)
		default:
			log.Printf("unknown function %s", fname)
			return
		}

	case "*crypto/tls.clientHandshakeStateTLS13":
		clientRandom = varToBytes(lookup(rcvr, "hello.random"))

		switch fname {
		case "crypto/tls.(*clientHandshakeStateTLS13).establishHandshakeKeys":
			serverSecret = varToBytes(lookup(rcvr, "c.in.trafficSecret"))
			clientSecret = varToBytes(lookup(rcvr, "c.out.trafficSecret"))
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelClientHandshake, clientRandom, clientSecret)
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelServerHandshake, clientRandom, serverSecret)
		case "crypto/tls.(*clientHandshakeStateTLS13).readServerFinished":
			serverSecret = varToBytes(lookup(rcvr, "c.in.trafficSecret"))
			clientSecret = varToBytes(lookup(rcvr, "trafficSecret"))
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelClientTraffic, clientRandom, clientSecret)
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelServerTraffic, clientRandom, serverSecret)
		default:
			log.Printf("unknown function %s", fname)
			return
		}

	case "*crypto/tls.serverHandshakeStateTLS13":
		clientRandom = varToBytes(lookup(rcvr, "clientHello.random"))

		switch fname {
		case "crypto/tls.(*serverHandshakeStateTLS13).sendServerParameters":
			serverSecret = varToBytes(lookup(rcvr, "c.out.trafficSecret"))
			clientSecret = varToBytes(lookup(rcvr, "c.in.trafficSecret"))
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelClientHandshake, clientRandom, clientSecret)
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelServerHandshake, clientRandom, serverSecret)
		case "crypto/tls.(*serverHandshakeStateTLS13).sendServerFinished":
			serverSecret = varToBytes(lookup(rcvr, "c.out.trafficSecret"))
			clientSecret = varToBytes(lookup(rcvr, "trafficSecret"))
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelClientTraffic, clientRandom, clientSecret)
			fmt.Fprintf(klw.w, "%s %x %x\n", keyLogLabelServerTraffic, clientRandom, serverSecret)
		default:
			log.Printf("unknown function %s", fname)
			return
		}

	default:
		log.Printf("unknown type signature with '%s' receiver", rcvr.Type)
	}
}

var (
	flagAttachPid  int
	flagAttachName string
	flagExecCmd    string

	flagTcpdump    bool
	flagDeviceName string

	flagLogFilename  string
	flagPcapFilename string
)

func main() {
	// debugger flags
	flag.IntVar(&flagAttachPid, "pid", 0, "Pid to attach to.")
	flag.StringVar(&flagAttachName, "process", "", "Process name to attach to.")
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
	var w io.Writer
	if flagLogFilename != "" && flagLogFilename != "-" {
		log.Printf("writing secrets to %s", flagLogFilename)
		f, err := os.OpenFile(flagLogFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = io.MultiWriter(f, os.Stdout)
	} else {
		w = os.Stdout
	}

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
	} else if flagAttachName != "" {
		pid, err = pidof(flagAttachName)
		if err != nil {
			log.Fatalf("failed to find pid: %s", err)
		}
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
		"crypto/tls.(*Config).writeKeyLog", true, nil)
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

	klw := NewKeyLogWriter(w)

	// Run the program, print key log on each breakpoint
	for {
		st := <-client.Continue()
		if st.Exited {
			log.Printf("process exited with status %d", st.ExitStatus)
			break
		}

		stack, err := client.Stacktrace(st.SelectedGoroutine.ID, 1, api.StacktraceSimple, nil)
		if err != nil {
			log.Fatalf("failed to fetch stacktrace: %s", err)
		}

		args, err := client.ListFunctionArgs(api.EvalScope{
			GoroutineID: st.SelectedGoroutine.ID,
			Frame:       1,
		}, api.LoadConfig{
			FollowPointers:     true,
			MaxStringLen:       256,
			MaxArrayValues:     256,
			MaxVariableRecurse: 4,
			MaxStructFields:    -1,
		})
		if err != nil {
			log.Fatalf("failed to list args: %s", err)
		}

		klw.WriteKeyLog(stack, args)
	}
}
