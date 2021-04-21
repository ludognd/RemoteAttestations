package mocks

import (
	"crypto/rsa"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
)

type MockAttestationKey struct {
	CatchSave      func(filePath string) error
	CatchPublicKey func() *rsa.PublicKey
	CatchBlob      func() []byte
}

var _ tpm.AttestationKey = (*MockAttestationKey)(nil) // Verify that *MockAttestationKey implements AttestationKey.

func (ak *MockAttestationKey) Save(filePath string) error {
	return ak.CatchSave(filePath)
}

func (ak *MockAttestationKey) PublicKey() *rsa.PublicKey {
	return ak.CatchPublicKey()
}

func (ak *MockAttestationKey) Blob() []byte {
	return ak.CatchBlob()
}
