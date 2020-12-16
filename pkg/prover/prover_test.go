package prover

import (
	"errors"
	"github.com/google/go-cmp/cmp"
	"github.com/xcaliburne/RemoteAttestations/pkg/tests"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/mocks"
	"github.com/xcaliburne/RemoteAttestations/pkg/verifier/tests/fakes"
	"testing"
)

var p Prover

func init() {
	p = Prover{}
}

func TestProver_IsInit(t *testing.T) {
	mockTPM := &mocks.MockTPM{}
	p.TPM = mockTPM
	want := false
	mockTPM.CatchIsOwned = func() (bool, error) {
		return false, nil
	}
	got, _ := p.IsInit()
	if got != want {
		t.Log(tests.Failure(t, got, want, ""))
	}

	want = true
	mockTPM.CatchIsOwned = func() (bool, error) {
		return true, nil
	}
	got, _ = p.IsInit()
	if got != want {
		t.Log(tests.Failure(t, got, want, ""))
	}
}

func TestProver_Attest(t *testing.T) {
	mockTPM := &mocks.MockTPM{}
	p.TPM = mockTPM
	want := mocks.GetFakeQuote()
	mockTPM.CatchQuote = func(ak tpm.AttestationKey, nonce []byte, pcrIds []int) (tpm.Quote, error) {
		return mocks.GetFakeQuote(), nil
	}
	got, _ := p.Attest(fakes.GetFakeNonce())
	if !cmp.Equal(got, want) {
		t.Log(tests.Failure(t, got, want, ""))
	}

	wantErr := errors.New("some error")
	mockTPM.CatchQuote = func(ak tpm.AttestationKey, nonce []byte, pcrIds []int) (tpm.Quote, error) {
		return nil, wantErr
	}
	_, gotErr := p.Attest(fakes.GetFakeNonce())
	if gotErr == nil {
		t.Error(tests.Failure(t, gotErr, wantErr, ""))
	}
}

func TestProver_load(t *testing.T) {
	//mockTPM := &mocks.MockTPM{}
	//mockEK := mocks.MockEndorsementKey{}
	//mockAk := mocks.MockAttesationKey{}
	//p.TPM = mockTPM
	//mockTPM.CatchProveOwnership = func(userPassword string) error {
	//	return nil
	//}
	//mockTPM.CatchProveUsership = func(userPassword string) error {
	//	return nil
	//}
	//mockTPM.CatchGetEK = func() (TPM.EndorsementKey, error) {
	//	return &mockEK, nil
	//}
	//mockTPM. = func() (TPM.EndorsementKey, error) {
	//	return &mocks.MockEndorsementKey{}, nil
	//}
	////want := (&mocks.MockQuote{}).GetFake()
	////mockTPM.CatchQuote = func(ak TPM.AttestationKey, nonce []byte, pcrIds []int) (TPM.Quote, error) {
	////	return (&mocks.MockQuote{}).GetFake(), nil
	////}
	////got, _ := p.Attest(fakes.GetFakeNonce())
	////if !cmp.Equal(got, want) {
	////	t.Log(tests.Failure(t, got, want,""))
	////}
	//t.Log(tests.Success(t))
}
