/* Copyright (c) 2014, Casey Marshall
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of this project nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package macaroons

/*
#cgo CFLAGS: -I../../..
#cgo LDFLAGS: -L../../../.libs -lmacaroons -lsodium
#include <stdio.h>
#include <stdlib.h>
#include "macaroons.h"
*/
import "C"

type Verifier struct {
	v *C.struct_macaroon_verifier
}

func NewVerifier() *Verifier {
	return &Verifier{v: C.macaroon_verifier_create()}
}

func (v *Verifier) Destroy() {
	C.macaroon_verifier_destroy(v.v)
}

func (v *Verifier) SatisfyExact(predicate string) error {
	var err C.enum_macaroon_returncode
	pred, predSz := cUStrN(predicate)
	rc := C.macaroon_verifier_satisfy_exact(v.v, pred, predSz, &err)
	if rc < 0 {
		return macaroonError(err)
	}
	return nil
}

/*
   int macaroon_verifier_satisfy_general(macaroon_verifier* V, int (*general_check)(void* f, const unsigned char* pred, size_t pred_sz), void* f, macaroon_returncode* err)
   int macaroon_verify(const macaroon_verifier* V, const macaroon* M, const unsigned char* key, size_t key_sz, macaroon** MS, size_t MS_sz, macaroon_returncode* err)
*/
