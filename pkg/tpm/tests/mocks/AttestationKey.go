package mocks

import (
	"crypto/rsa"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
)

type MockAttesationKey struct {
	CatchSave      func(filePath string) error
	CatchPublicKey func() *rsa.PublicKey
	CatchBlob      func() []byte
}

var _ tpm.AttestationKey = (*MockAttesationKey)(nil) // Verify that *MockAttesationKey implements AttestationKey.

func (ak *MockAttesationKey) Save(filePath string) error {
	return ak.CatchSave(filePath)
}

func (ak *MockAttesationKey) PublicKey() *rsa.PublicKey {
	return ak.CatchPublicKey()
}

func (ak *MockAttesationKey) Blob() []byte {
	return ak.CatchBlob()
}
