// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build dragonfly || freebsd || netbsd
// +build dragonfly freebsd netbsd

package bsdbpf

import "unsafe"

// bpfAlignment matches BPF_ALIGNMENT in the kernel's net/bpf.h, which is
// sizeof(long) on FreeBSD, NetBSD and DragonFly. 32-bit processes on 64-bit
// FreeBSD/NetBSD kernels get 32-bit alignment via the kernel's compat32
// path, which still equals the size of a native pointer here.
const bpfAlignment = int(unsafe.Sizeof(uintptr(0)))
