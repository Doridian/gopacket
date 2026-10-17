// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build darwin || dragonfly || freebsd || netbsd || openbsd
// +build darwin dragonfly freebsd netbsd openbsd

package bsdbpf

import (
	"bytes"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// kernelBpfAlignment is BPF_ALIGNMENT from each kernel's net/bpf.h, spelled
// out independently of bpfAlignment so the test catches a wrong value.
func kernelBpfAlignment() int {
	switch runtime.GOOS {
	case "darwin", "openbsd":
		return 4 // sizeof(int32_t) / sizeof(u_int32_t)
	default:
		return int(unsafe.Sizeof(uintptr(0))) // sizeof(long)
	}
}

// packBpfFrames lays out frames the way the kernel does in a read() buffer:
// each record is a header plus captured bytes, and the next record starts at
// the BPF_WORDALIGN'ed offset. The last record is not padded.
func packBpfFrames(frames [][]byte, align int) []byte {
	// bh_hdrlen as the kernel computes it for an Ethernet link header.
	const linkHdrLen = 14
	sizeofBpfHdr := int(unsafe.Offsetof(unix.BpfHdr{}.Hdrlen) + unsafe.Sizeof(unix.BpfHdr{}.Hdrlen))
	hdrlen := ((linkHdrLen+sizeofBpfHdr)+(align-1))&^(align-1) - linkHdrLen

	// Extra capacity so the trailing BpfHdr padding never straddles the allocation.
	buf := make([]byte, 0, 64*1024)
	for i, frame := range frames {
		off := len(buf)
		buf = append(buf, make([]byte, hdrlen)...)
		hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[off]))
		hdr.Hdrlen = uint16(hdrlen)
		hdr.Caplen = uint32(len(frame))
		hdr.Datalen = uint32(len(frame))
		buf = append(buf, frame...)
		if i < len(frames)-1 {
			for len(buf)%align != 0 {
				buf = append(buf, 0xAA)
			}
		}
	}
	return buf
}

func TestNextBpfFrameKernelLayout(t *testing.T) {
	align := kernelBpfAlignment()
	if bpfAlignment != align {
		t.Fatalf("bpfAlignment = %d, kernel BPF_ALIGNMENT = %d", bpfAlignment, align)
	}

	var frames [][]byte
	// Lengths covering every remainder mod 8, e.g. 63 + 18 = 81 rounds to 84
	// with 4-byte alignment but to 88 with 8-byte alignment.
	for i, n := range []int{63, 60, 61, 62, 64, 65, 66, 67, 1500, 14, 63, 90} {
		frame := make([]byte, n)
		for j := range frame {
			frame[j] = byte(i*31 + j)
		}
		frames = append(frames, frame)
	}

	buf := packBpfFrames(frames, align)
	off := 0
	for i, want := range frames {
		hdr, got, next, err := nextBpfFrame(buf, off)
		if err != nil {
			t.Fatalf("frame %d at offset %d: %v", i, off, err)
		}
		if int(hdr.Caplen) != len(want) || !bytes.Equal(got, want) {
			t.Fatalf("frame %d at offset %d: got %d bytes, want %d intact bytes", i, off, len(got), len(want))
		}
		off = next
	}
	if off < len(buf) {
		t.Fatalf("%d trailing bytes left after the last frame", len(buf)-off)
	}
}

func TestNextBpfFrameCorrupt(t *testing.T) {
	buf := packBpfFrames([][]byte{make([]byte, 60)}, kernelBpfAlignment())

	// Header does not fit.
	if _, _, next, err := nextBpfFrame(buf[:bpfHdrSize-1], 0); err == nil || next != bpfHdrSize-1 {
		t.Fatalf("short header: err=%v next=%d", err, next)
	}

	// Caplen points past the bytes actually read: the rest must be discarded.
	short := buf[:len(buf)-1]
	if _, _, next, err := nextBpfFrame(short, 0); err == nil || next != len(short) {
		t.Fatalf("truncated frame: err=%v next=%d", err, next)
	}

	// A zero bh_hdrlen would never advance.
	zero := make([]byte, len(buf))
	if _, _, next, err := nextBpfFrame(zero, 0); err == nil || next != len(zero) {
		t.Fatalf("zero header: err=%v next=%d", err, next)
	}
}
