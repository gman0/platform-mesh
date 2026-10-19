/*
Copyright The Platform Mesh Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bundle

import (
	"errors"
	"fmt"
)

// Reason is the stable cause of a refused bundle, sent as the Detail of a
// BundleInvalid refusal.
type Reason string

const (
	ReasonTooLarge             Reason = "TooLarge"
	ReasonTooMany              Reason = "TooManyCertificates"
	ReasonTextOutsideBlocks    Reason = "TextOutsideBlocks"
	ReasonMalformedPEM         Reason = "MalformedPEM"
	ReasonNotCertificate       Reason = "NotCertificate"
	ReasonPEMHeaders           Reason = "PEMHeaders"
	ReasonMalformedCertificate Reason = "MalformedCertificate"
	ReasonNotCA                Reason = "NotCA"
	ReasonDuplicate            Reason = "Duplicate"
	ReasonEmpty                Reason = "Empty"
	ReasonAllExpired           Reason = "AllExpired"
)

// Error is a refused bundle.
type Error struct {
	Reason Reason
	// Block is the index of the offending PEM block, or -1 for the bundle
	// as a whole.
	Block int
	Err   error
}

func newError(r Reason, block int, err error) *Error {
	return &Error{Reason: r, Block: block, Err: err}
}

func (e *Error) Error() string {
	msg := "pinned bundle refused: " + string(e.Reason)
	if e.Block >= 0 {
		msg += fmt.Sprintf(" (block %d)", e.Block)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// ReasonOf returns the Reason of a bundle error.
func ReasonOf(err error) (Reason, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason, true
	}
	return "", false
}
