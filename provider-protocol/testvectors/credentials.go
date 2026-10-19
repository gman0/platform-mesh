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

import "strings"

// A fixed, valid Onboarding Token and its parts.
const (
	TokenBaseURL     = "https://wildwest.example.com/pm"
	TokenBaseURLB64  = "aHR0cHM6Ly93aWxkd2VzdC5leGFtcGxlLmNvbS9wbQ"
	TokenKeyHex      = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
	TokenID          = "t-abcdefghijklmnopqrstuvwxyz"
	TokenSecret      = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	TokenSecretHash  = "sha256:ea866a757e4c38babfa8127cbe9a409d3e1f93a00ff1488ff735fcf917afffd0"
	Token            = "pm1." + TokenBaseURLB64 + "." + TokenKeyHex + "." + TokenID + "." + TokenSecret
	TokenServerKeyFP = "key-sha256:" + TokenKeyHex
)

// A fixed, valid Connection Secret and its hash.
const (
	ConnectionSecret     = "pmc1_ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
	ConnectionSecretHash = "sha256:910ecc3381e0dd03ae410841fc49a08272ab3239ca4725d609721331ecaf47eb"
)

// TextCase is a text input and whether it's valid.
type TextCase struct {
	Name  string
	Text  string
	Valid bool
}

// OnboardingTokens are Onboarding Token texts.
func OnboardingTokens() []TextCase {
	join := func(parts ...string) string { return strings.Join(parts, ".") }
	return []TextCase{
		{"valid", Token, true},
		{"empty", "", false},
		{"four parts", join("pm1", TokenBaseURLB64, TokenKeyHex, TokenID), false},
		{"six parts", Token + ".x", false},
		{"other version", join("pm2", TokenBaseURLB64, TokenKeyHex, TokenID, TokenSecret), false},
		{"base URL padded", join("pm1", TokenBaseURLB64+"=", TokenKeyHex, TokenID, TokenSecret), false},
		{"base URL with newline", join("pm1", TokenBaseURLB64[:4]+"\n"+TokenBaseURLB64[4:], TokenKeyHex, TokenID, TokenSecret), false},
		{"base URL http", join("pm1", "aHR0cDovL3dpbGR3ZXN0LmV4YW1wbGUuY29t", TokenKeyHex, TokenID, TokenSecret), false},
		{"key with kind", join("pm1", TokenBaseURLB64, TokenServerKeyFP, TokenID, TokenSecret), false},
		{"key uppercase", join("pm1", TokenBaseURLB64, strings.ToUpper(TokenKeyHex), TokenID, TokenSecret), false},
		{"key short", join("pm1", TokenBaseURLB64, TokenKeyHex[:63], TokenID, TokenSecret), false},
		{"Connection ID as token ID", join("pm1", TokenBaseURLB64, TokenKeyHex, "c-"+TokenID[2:], TokenSecret), false},
		{"secret short", join("pm1", TokenBaseURLB64, TokenKeyHex, TokenID, TokenSecret[:42]), false},
		{"secret padded", join("pm1", TokenBaseURLB64, TokenKeyHex, TokenID, TokenSecret+"="), false},
		{"secret with CR", join("pm1", TokenBaseURLB64, TokenKeyHex, TokenID, TokenSecret[:10]+"\r"+TokenSecret[10:]), false},
		{"trailing newline", Token + "\n", false},
		{"leading space", " " + Token, false},
	}
}

// ConnectionSecrets are Connection Secret texts.
func ConnectionSecrets() []TextCase {
	body := strings.TrimPrefix(ConnectionSecret, "pmc1_")
	return []TextCase{
		{"valid", ConnectionSecret, true},
		{"empty", "", false},
		{"no prefix", body, false},
		{"other version", "pmc2_" + body, false},
		{"prefix only", "pmc1_", false},
		{"short", "pmc1_" + body[:42], false},
		{"long", "pmc1_" + body + "A", false},
		{"padded", "pmc1_" + body + "=", false},
		{"standard alphabet", "pmc1_" + strings.Repeat("+", 43), false},
		{"trailing newline", ConnectionSecret + "\n", false},
		{"inner newline", "pmc1_" + body[:20] + "\n" + body[20:], false},
	}
}

// Hashes are secret hash texts.
func Hashes() []TextCase {
	digits := strings.TrimPrefix(ConnectionSecretHash, "sha256:")
	return []TextCase{
		{"valid", ConnectionSecretHash, true},
		{"no prefix", digits, false},
		{"other algorithm", "sha512:" + digits, false},
		{"prefix uppercase", "SHA256:" + digits, false},
		{"hex uppercase", "sha256:" + strings.ToUpper(digits), false},
		{"short", "sha256:" + digits[:63], false},
		{"fingerprint", "key-sha256:" + digits, false},
	}
}

// Fingerprints are fingerprint texts; valid ones may be of either kind.
func Fingerprints() []TextCase {
	return []TextCase{
		{"key", TokenServerKeyFP, true},
		{"cert", "cert-sha256:" + TokenKeyHex, true},
		{"no kind", TokenKeyHex, false},
		{"unknown kind", "sha256:" + TokenKeyHex, false},
		{"uppercase hex", "key-sha256:" + strings.ToUpper(TokenKeyHex), false},
		{"openssl style", "key-sha256:" + colonPairs(TokenKeyHex), false},
		{"short", "key-sha256:" + TokenKeyHex[:63], false},
		{"trailing space", TokenServerKeyFP + " ", false},
	}
}

func colonPairs(hex string) string {
	pairs := make([]string, 0, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		pairs = append(pairs, hex[i:i+2])
	}
	return strings.Join(pairs, ":")
}
