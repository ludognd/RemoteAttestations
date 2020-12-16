package mocks

import (
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
)

type MockTPM struct {
	CatchClose          func() error
	CatchTakeOwnership  func(ownerPassword, userPassword string) error
	CatchIsOwned        func() (bool, error)
	CatchProveOwnership func(ownerPassword string) error
	CatchProveUsership  func(userPassword string) error
	CatchGetEK          func() (tpm.EndorsementKey, error)
	CatchCreateAK       func() (tpm.AttestationKey, error)
	CatchQuote          func(ak tpm.AttestationKey, nonce []byte, pcrIds []int) (tpm.Quote, error)
	CatchListPCRs       func() []tpm.PCR
	CatchExtendPCR      func(pcr tpm.PCR, data []byte) error
}

var _ tpm.TPM = (*MockTPM)(nil) // Verify that a pointer to a MockTPM implements TPM.

func (t *MockTPM) Close() error {
	//default behavior
	if t.CatchClose == nil {
		return nil
	}
	return t.CatchClose()
}

func (t *MockTPM) TakeOwnership(ownerPassword, userPassword string) error {
	//default behavior
	if t.CatchTakeOwnership == nil {
		return nil
	}
	return t.CatchTakeOwnership(ownerPassword, userPassword)
}

func (t *MockTPM) IsOwned() (bool, error) {
	//default behavior
	if t.CatchIsOwned == nil {
		return false, nil
	}
	return t.CatchIsOwned()
}

func (t *MockTPM) ProveOwnership(ownerPassword string) error {
	//default behavior
	if t.CatchProveOwnership == nil {
		return nil
	}
	return t.CatchProveOwnership(ownerPassword)
}

func (t *MockTPM) ProveUsership(userPassword string) error {
	//default behavior
	if t.CatchProveUsership == nil {
		return nil
	}
	return t.CatchProveUsership(userPassword)
}

func (t *MockTPM) GetEK() (tpm.EndorsementKey, error) {
	//default behavior
	if t.CatchGetEK == nil {
		return &tpm.EndorsementKeyData{}, nil
	}
	return t.CatchGetEK()
}

func (t *MockTPM) CreateAK() (tpm.AttestationKey, error) {
	//default behavior
	if t.CatchCreateAK == nil {
		return &tpm.AttestationKeyData{}, nil
	}
	return t.CatchCreateAK()
}

func (t *MockTPM) Quote(ak tpm.AttestationKey, nonce []byte, pcrIds []int) (tpm.Quote, error) {
	//default behavior
	if t.CatchQuote == nil {
		return &tpm.QuoteData{}, nil
	}
	return t.CatchQuote(ak, nonce, pcrIds)
}

func (t *MockTPM) ListPCRs() []tpm.PCR {
	//default behavior
	if t.CatchListPCRs == nil {
		return []tpm.PCR{}
	}
	return t.CatchListPCRs()
}

func (t *MockTPM) ExtendPCR(pcr tpm.PCR, data []byte) error {
	//default *behavior
	if t.CatchExtendPCR == nil {
		return nil
	}
	return t.CatchExtendPCR(pcr, data)
}
