package mocks

import (
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
)

type MockProver struct {
	CatchRegister func(restIP, restPort string) error
	CatchAttest   func(nonce []byte) (tpm.Quote, error)
}

func (m *MockProver) Register(restIP, restPort string) error {
	return m.CatchRegister(restIP, restPort)
}

func (m *MockProver) Attest(nonce []byte) (tpm.Quote, error) {
	return m.CatchAttest(nonce)
}
