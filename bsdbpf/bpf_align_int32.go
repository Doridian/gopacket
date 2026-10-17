// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build darwin || openbsd
// +build darwin openbsd

package bsdbpf

// bpfAlignment matches BPF_ALIGNMENT in the kernel's net/bpf.h, which is
// sizeof(int32_t) on XNU and sizeof(u_int32_t) on OpenBSD, independent of
// the word size of the architecture.
const bpfAlignment = 4
