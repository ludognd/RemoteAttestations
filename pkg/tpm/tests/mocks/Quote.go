package mocks

import (
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
)

type MockQuote struct {
	CatchVerify     func(ak tpm.AttestationKey, nonce []byte) error
	CatchVerifyPCRs func(pcrs []tpm.PCR) error
	CatchUnmarshal  func(data []byte) error
}

var _ tpm.Quote = (*MockQuote)(nil) // Verify that *MockQuote implements Quote.

func (q *MockQuote) Verify(ak tpm.AttestationKey, nonce []byte) error {
	return q.CatchVerify(ak, nonce)
}

func (q *MockQuote) VerifyPCRs(pcrs []tpm.PCR) error {
	return q.CatchVerifyPCRs(pcrs)
}

func (q *MockQuote) UnmarshalJSON(data []byte) error {
	return q.CatchUnmarshal(data)
}
