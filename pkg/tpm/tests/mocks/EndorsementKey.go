package mocks

import (
	"crypto/rsa"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
)

type MockEndorsementKey struct {
	CatchVerifyEKCert func() error
	CatchPublicKey    func() *rsa.PublicKey
	CatchCertificate  func() *x509.Certificate
}

var _ tpm.EndorsementKey = (*MockEndorsementKey)(nil) // Verify that *MockEndorsementKey implements EndorsementKey.

func (ek *MockEndorsementKey) VerifyEKCert() error {
	return ek.CatchVerifyEKCert()
}

func (ek *MockEndorsementKey) PublicKey() *rsa.PublicKey {
	return ek.CatchPublicKey()
}
func (ek *MockEndorsementKey) Certificate() *x509.Certificate {
	return ek.CatchCertificate()
}
