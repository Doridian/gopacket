// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build darwin || dragonfly || freebsd || netbsd || openbsd
// +build darwin dragonfly freebsd netbsd openbsd

package bsdbpf

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/Doridian/gopacket"
	"golang.org/x/sys/unix"
)

// bpfAlignment mirrors the kernel's BPF_ALIGNMENT and is defined per OS
// in bpf_align_*.go, since it is not the same on every BSD.
func bpfWordAlign(x int) int {
	return ((x) + (bpfAlignment - 1)) &^ (bpfAlignment - 1)
}

const bpfHdrSize = int(unsafe.Sizeof(unix.BpfHdr{}))

var errCorruptBpfHdr = errors.New("BPF captured frame received with corrupted BpfHdr struct.")

// nextBpfFrame parses the BPF header found at offset off of buf, which must
// contain exactly the bytes returned by read(). It returns the header (nil if
// not even a full header fits), the captured frame and the offset of the
// next header. On error the returned offset is len(buf), so that the rest
// of the buffer is discarded.
func nextBpfFrame(buf []byte, off int) (*unix.BpfHdr, []byte, int, error) {
	if off < 0 || off+bpfHdrSize > len(buf) {
		return nil, nil, len(buf), errCorruptBpfHdr
	}
	hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[off]))
	frameStart := off + int(hdr.Hdrlen)
	frameEnd := frameStart + int(hdr.Caplen)
	if hdr.Hdrlen == 0 || frameEnd > len(buf) {
		return hdr, nil, len(buf), errCorruptBpfHdr
	}
	return hdr, buf[frameStart:frameEnd], off + bpfWordAlign(frameEnd-off), nil
}

// Options is used to configure various properties of the BPF sniffer.
// Default values are used when a nil Options pointer is passed to NewBPFSniffer.
type Options struct {
	// BPFDeviceName is name of the bpf device to use for sniffing
	// the network device. The default value of BPFDeviceName is empty string
	// which causes the first available BPF device file /dev/bpfX to be used.
	BPFDeviceName string
	// ReadBufLen specifies the size of the buffer used to read packets
	// off the wire such that multiple packets are buffered with each read syscall.
	// Note that an individual packet larger than the buffer size is necessarily truncated.
	// A larger buffer should increase performance because fewer read syscalls would be made.
	// If zero is used, the system's default buffer length will be used which depending on the
	// system may default to 4096 bytes which is not big enough to accomodate some link layers
	// such as WLAN (802.11).
	// ReadBufLen defaults to 32767... however typical BSD manual pages for BPF indicate that
	// if the requested buffer size cannot be accommodated, the closest allowable size will be
	// set and returned... hence our GetReadBufLen method.
	ReadBufLen int
	// Timeout is the length of time to wait before timing out on a read request.
	// Timeout defaults to nil which means no timeout is used.
	Timeout *syscall.Timeval
	// Promisc is set to true for promiscuous mode ethernet sniffing.
	// Promisc defaults to true.
	Promisc bool
	// Immediate is set to true to make our read requests return as soon as a packet becomes available.
	// Otherwise, a read will block until either the kernel buffer becomes full or a timeout occurs.
	// The default is true.
	Immediate bool
	// PreserveLinkAddr is set to false if the link level source address should be filled in automatically
	// by the interface output routine. Set to true if the link level source address will be written,
	// as provided, to the wire.
	// The default is true.
	PreserveLinkAddr bool
	// SeeSent is set to false if locally generated packets on the interface should not be returned by BPF.
	// The default is true.
	SeeSent bool
}

var defaultOptions = Options{
	BPFDeviceName:    "",
	ReadBufLen:       32767,
	Timeout:          nil,
	Promisc:          true,
	Immediate:        true,
	PreserveLinkAddr: true,
	SeeSent:          true,
}

// BPFSniffer is a struct used to track state of a BSD BPF ethernet sniffer
// such that gopacket's PacketDataSource interface is implemented.
type BPFSniffer struct {
	options           *Options
	sniffDeviceName   string
	fd                int
	readBuffer        []byte
	lastReadLen       int
	readBytesConsumed int
}

// NewBPFSniffer is used to create BSD-only BPF ethernet sniffer
// iface is the network interface device name that you wish to sniff
// options can set to nil in order to utilize default values for everything.
// Each field of Options also have a default setting if left unspecified by
// the user's custome Options struct.
func NewBPFSniffer(iface string, options *Options) (*BPFSniffer, error) {
	var err error
	enable := 1
	sniffer := BPFSniffer{
		sniffDeviceName: iface,
	}
	if options == nil {
		sniffer.options = &defaultOptions
	} else {
		sniffer.options = options
	}

	sniffer.pickBpfDevice()

	// setup our read buffer
	if sniffer.options.ReadBufLen == 0 {
		sniffer.options.ReadBufLen, err = syscall.BpfBuflen(sniffer.fd)
		if err != nil {
			goto err
		}
	} else {
		sniffer.options.ReadBufLen, err = syscall.SetBpfBuflen(sniffer.fd, sniffer.options.ReadBufLen)
		if err != nil {
			goto err
		}
	}
	sniffer.readBuffer = make([]byte, sniffer.options.ReadBufLen)

	err = syscall.SetBpfInterface(sniffer.fd, sniffer.sniffDeviceName)
	if err != nil {
		goto err
	}

	if sniffer.options.Immediate {
		// turn immediate mode on. This makes the snffer non-blocking.
		err = syscall.SetBpfImmediate(sniffer.fd, enable)
		if err != nil {
			goto err
		}
	}

	// the above call to syscall.SetBpfImmediate needs to be made
	// before setting a timer otherwise the reads will block for the
	// entire timer duration even if there are packets to return.
	if sniffer.options.Timeout != nil {
		err = syscall.SetBpfTimeout(sniffer.fd, sniffer.options.Timeout)
		if err != nil {
			goto err
		}
	}

	if sniffer.options.PreserveLinkAddr {
		// preserves the link level source address...
		// higher level protocol analyzers will not need this
		err = syscall.SetBpfHeadercmpl(sniffer.fd, enable)
		if err != nil {
			goto err
		}
	}

	if sniffer.options.Promisc {
		// forces the interface into promiscuous mode
		err = syscall.SetBpfPromisc(sniffer.fd, enable)
		if err != nil {
			goto err
		}
	}

	if !sniffer.options.SeeSent {
		// See sent is set by default, need to turn it off
		err = unix.IoctlSetPointerInt(sniffer.fd, syscall.BIOCSSEESENT, 0)
		if err != nil {
			goto err
		}
	}

	return &sniffer, nil
err:
	syscall.Close(sniffer.fd)
	return nil, err
}

// Close is used to close the file-descriptor of the BPF device file.
func (b *BPFSniffer) Close() error {
	return syscall.Close(b.fd)
}

func (b *BPFSniffer) pickBpfDevice() {
	var err error
	if len(b.options.BPFDeviceName) > 0 {
		b.fd, err = syscall.Open(b.options.BPFDeviceName, syscall.O_RDWR, 0)
		if err == nil {
			return
		}
	} else {
		b.options.BPFDeviceName = ""
		for i := 0; i < 99; i++ {
			name := fmt.Sprintf("/dev/bpf%d", i)
			b.fd, err = syscall.Open(name, syscall.O_RDWR, 0)
			if err == nil {
				b.options.BPFDeviceName = name
				return
			}

			if err == syscall.Errno(syscall.ENOENT) {
				// No such file, no needs to iterate further
				break
			}
		}
	}
	panic("failed to acquire a BPF device for read-write access")
}

func (b *BPFSniffer) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	var err error
	if b.readBytesConsumed >= b.lastReadLen {
		b.readBytesConsumed = 0
		b.readBuffer = make([]byte, b.options.ReadBufLen)
		b.lastReadLen, err = syscall.Read(b.fd, b.readBuffer)
		if err != nil {
			b.lastReadLen = 0
			return nil, gopacket.CaptureInfo{}, err
		}
	}
	if b.lastReadLen == 0 {
		return b.readBuffer[:0], gopacket.CaptureInfo{}, nil
	}

	hdr, rawFrame, next, err := nextBpfFrame(b.readBuffer[:b.lastReadLen], b.readBytesConsumed)
	b.readBytesConsumed = next
	if err != nil {
		captureInfo := gopacket.CaptureInfo{}
		if hdr != nil {
			captureInfo.Timestamp = time.Unix(int64(hdr.Tstamp.Sec), int64(hdr.Tstamp.Usec)*1000)
		}
		return nil, captureInfo, err
	}

	captureInfo := gopacket.CaptureInfo{
		Timestamp:     time.Unix(int64(hdr.Tstamp.Sec), int64(hdr.Tstamp.Usec)*1000),
		CaptureLength: len(rawFrame),
		Length:        len(rawFrame),
	}
	return rawFrame, captureInfo, nil
}

// GetReadBufLen returns the BPF read buffer length
func (b *BPFSniffer) GetReadBufLen() int {
	return b.options.ReadBufLen
}

func (h *BPFSniffer) WritePacketData(pkt []byte) error {
	_, err := unix.Write(h.fd, pkt)
	return err
}
