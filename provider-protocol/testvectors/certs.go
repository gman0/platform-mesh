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

package testvectors

import "go.platform-mesh.io/provider-protocol/internal/testcerts"

// The certificate factory, for other modules' tests.

// Now is the time vector certificates are valid around.
var Now = testcerts.Now

// Cert is a certificate and its key.
type Cert = testcerts.Cert

// Opt changes a certificate before signing.
type Opt = testcerts.Opt

var (
	// CA returns a self-signed Connector CA, or one signed by a parent.
	CA = testcerts.CA
	// Leaf returns a Connector Certificate issued by a CA.
	Leaf = testcerts.Leaf
	// Join concatenates PEM blocks.
	Join = testcerts.Join

	Expired            Opt = testcerts.Expired
	NotCA              Opt = testcerts.NotCA
	NoCertSign         Opt = testcerts.NoCertSign
	NoEKU              Opt = testcerts.NoEKU
	ServerEKU          Opt = testcerts.ServerEKU
	NoDigitalSignature Opt = testcerts.NoDigitalSignature
)
