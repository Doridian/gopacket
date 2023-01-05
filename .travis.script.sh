#!/bin/bash

set -ev

go test github.com/Doridian/gopacket
go test github.com/Doridian/gopacket/layers
go test github.com/Doridian/gopacket/tcpassembly
go test github.com/Doridian/gopacket/reassembly
go test github.com/Doridian/gopacket/pcapgo
go test github.com/Doridian/gopacket/pcap
sudo $(which go) test github.com/Doridian/gopacket/routing
