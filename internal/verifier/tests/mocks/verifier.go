package mocks

import (
	"github.com/xcaliburne/RemoteAttestations/internal/verifier"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
)

type MockVerifier struct {
	CatchInitParams         func() verifier.InitializationParams
	CatchRegisterNewEK      func(p *verifier.Prover) error
	CatchRegisterNewAK      func(p *verifier.Prover) error
	CatchAttestationRequest func(nonce []byte, url string) (tpm.Quote, error)
	CatchStartAttestations  func()
	CatchGetChallenge       func() ([]byte, error)
}

var _ verifier.Verifier = (*MockVerifier)(nil) // Verify that *MockEndorsementKey implements EndorsementKey.

func (v *MockVerifier) InitParams() verifier.InitializationParams {
	return v.CatchInitParams()
}
func (v *MockVerifier) RegisterNewEK(p *verifier.Prover) error {
	return v.CatchRegisterNewEK(p)
}
func (v *MockVerifier) RegisterNewAK(p *verifier.Prover) error {
	return v.CatchRegisterNewAK(p)
}
func (v *MockVerifier) AttestationRequest(nonce []byte, url string) (tpm.Quote, error) {
	return v.CatchAttestationRequest(nonce, url)
}
func (v *MockVerifier) StartAttestations() {
	v.CatchStartAttestations()
}
func (v *MockVerifier) GetChallenge() ([]byte, error) {
	return v.CatchGetChallenge()
}
