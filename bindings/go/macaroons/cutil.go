// Copyright 2013 The Go-SQLite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Adapted from github.com/mxk/go-sqlite/sqlite3/util.go by
// Casey Marshall <cmars@cmarstech.com>

package macaroons

import "C"

import (
	"reflect"
	"unsafe"
)

// cStrN returns a char* pointer to the first byte in s and the byte length of
// the string.
func cStrN(s string) (*C.char, C.size_t) {
	h := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return (*C.char)(unsafe.Pointer(h.Data)), C.size_t(len(s))
}

// cUStrN returns an unsigned char* pointer to the first byte in s and the byte
// length of the string.
func cUStrN(s string) (*C.uchar, C.size_t) {
	h := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return (*C.uchar)(unsafe.Pointer(h.Data)), C.size_t(len(s))
}

// cBytes returns a pointer to the first byte in b.
func cBytes(b []byte) *C.char {
	return (*C.char)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&b)).Data))
}
