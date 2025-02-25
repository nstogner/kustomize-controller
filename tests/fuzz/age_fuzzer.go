//go:build gofuzz
// +build gofuzz

/*
Copyright 2022 The Flux authors

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

package age

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

// FuzzAge implements a fuzzer that targets functions within age/keysource.go.
func FuzzAge(data []byte) int {
	f := fuzz.NewConsumer(data)
	masterKey := MasterKey{}

	if err := f.GenerateStruct(&masterKey); err != nil {
		return 0
	}

	_ = masterKey.Encrypt(data)
	_ = masterKey.EncryptIfNeeded(data)

	receipt, err := f.GetString()
	if err != nil {
		return 0
	}
	_, _ = MasterKeyFromRecipient(receipt)

	identities, err := f.GetString()
	if err != nil {
		return 0
	}
	_, _ = MasterKeyFromIdentities(identities)

	return 1
}
