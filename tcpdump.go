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
package main

import (
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func PacketCapture(filename, deviceName string) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("error creating pcap file: %s", err)
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	defer f.Close()

	log.Printf("writing pcap to %s", filename)

	// Open the device for capturing
	handle, err := pcap.OpenLive(deviceName, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("error opening device %s: %s", deviceName, err)
	}
	defer handle.Close()

	// Start processing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
}
