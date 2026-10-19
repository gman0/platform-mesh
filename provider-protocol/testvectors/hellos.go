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

import (
	"encoding/binary"
	"strings"

	connectionsv1 "go.platform-mesh.io/provider-protocol/connections/v1"
)

// The Connection a valid Hello is for.
const (
	HelloConnectionID = "c-abcdefghijklmnopqrstuvwxyz"
	HelloClusterName  = "2x8k9abc"
	HelloHost         = "nereus.kcp.example.com:443"
)

// HelloFrameCase is a Hello frame as read from a Session, and the error
// reading it gives: nil, connectionsv1.ErrHelloMalformed or
// connectionsv1.ErrHelloTooLarge. A truncated frame gives another error.
type HelloFrameCase struct {
	Name  string
	Frame []byte
	Err   error
}

// HelloFrame frames a JSON body with its length.
func HelloFrame(body string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)
}

func helloJSON(fields ...string) string { return "{" + strings.Join(fields, ",") + "}" }

// HelloFrames are Hellos as they arrive.
func HelloFrames() []HelloFrameCase {
	id := `"connectionID":"` + HelloConnectionID + `"`
	cluster := `"clusterName":"` + HelloClusterName + `"`
	hosts := `"hosts":["` + HelloHost + `"]`
	malformed := connectionsv1.ErrHelloMalformed

	return []HelloFrameCase{
		{"valid", HelloFrame(helloJSON(id, cluster, hosts, `"sub":"0f3a"`)), nil},
		{"valid without sub", HelloFrame(helloJSON(id, cluster, hosts)), nil},
		{"two hosts during a rename", HelloFrame(helloJSON(id, cluster, `"hosts":["old.kcp.example.com","new.kcp.example.com"]`)), nil},
		{"unknown field", HelloFrame(helloJSON(id, cluster, hosts, `"addedLater":1`)), nil},

		{"empty", []byte{0, 0}, connectionsv1.ErrHelloTooLarge},
		{"oversized", append(binary.BigEndian.AppendUint16(nil, connectionsv1.MaxHelloSize+1), make([]byte, connectionsv1.MaxHelloSize+1)...), connectionsv1.ErrHelloTooLarge},
		{"not JSON", HelloFrame("hello"), malformed},
		{"data after the object", HelloFrame(helloJSON(id, cluster, hosts) + "{}"), malformed},
		{"missing connectionID", HelloFrame(helloJSON(cluster, hosts)), malformed},
		{"token ID as connectionID", HelloFrame(helloJSON(`"connectionID":"t-abcdefghijklmnopqrstuvwxyz"`, cluster, hosts)), malformed},
		{"missing clusterName", HelloFrame(helloJSON(id, hosts)), malformed},
		{"workspace path as clusterName", HelloFrame(helloJSON(id, `"clusterName":"root:providers:wildwest"`, hosts)), malformed},
		{"system cluster", HelloFrame(helloJSON(id, `"clusterName":"system:admin"`, hosts)), malformed},
		{"missing hosts", HelloFrame(helloJSON(id, cluster)), malformed},
		{"empty hosts", HelloFrame(helloJSON(id, cluster, `"hosts":[]`)), malformed},
		{"host with scheme", HelloFrame(helloJSON(id, cluster, `"hosts":["https://nereus.kcp.example.com"]`)), malformed},
		{"host with path", HelloFrame(helloJSON(id, cluster, `"hosts":["nereus.kcp.example.com/services"]`)), malformed},
		{"host uppercase", HelloFrame(helloJSON(id, cluster, `"hosts":["Nereus.kcp.example.com"]`)), malformed},
		{"duplicate host", HelloFrame(helloJSON(id, cluster, `"hosts":["a.example.com","a.example.com"]`)), malformed},
		{"too many hosts", HelloFrame(helloJSON(id, cluster, `"hosts":["a","b","c","d","e"]`)), malformed},
		{"sub with whitespace", HelloFrame(helloJSON(id, cluster, hosts, `"sub":"a b"`)), malformed},
	}
}

// HelloCheckCase is a valid Hello on a Session, with the Session path's
// Connection ID and the cluster name stored at Registration.
type HelloCheckCase struct {
	Name         string
	Hello        connectionsv1.Hello
	PathID       string
	ClusterName  string
	Valid        bool
}

// HelloChecks are the Session's essential check.
func HelloChecks() []HelloCheckCase {
	h := connectionsv1.Hello{ConnectionID: HelloConnectionID, ClusterName: HelloClusterName, Hosts: []string{HelloHost}}
	return []HelloCheckCase{
		{"matches", h, HelloConnectionID, HelloClusterName, true},
		{"path rewritten to another Connection", h, "c-zyxwvutsrqponmlkjihgfedcba", HelloClusterName, false},
		{"another Provider Workspace", h, HelloConnectionID, "other1", false},
	}
}
