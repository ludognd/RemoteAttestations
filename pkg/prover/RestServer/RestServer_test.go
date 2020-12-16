package RestServer

import (
	"bytes"
	"encoding/json"

	"github.com/xcaliburne/RemoteAttestations/pkg/prover"
	"github.com/xcaliburne/RemoteAttestations/pkg/tests"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/mocks"
	"github.com/xcaliburne/RemoteAttestations/pkg/verifier/tests/fakes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func init() {
	p = &prover.Prover{}
}
func TestTest(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	res := httptest.NewRecorder()

	want := "Hello World!"
	test(res, req)
	got := res.Body.String()
	if got != want {
		t.Error(tests.Failure(t, got, want, ""))
	}
}

func TestAttest(t *testing.T) {
	mockTPM := mocks.MockTPM{}
	p.TPM = &mockTPM

	want := mocks.GetFakeQuote()
	mockTPM.CatchQuote = func(ak tpm.AttestationKey, nonce []byte, pcrIds []int) (tpm.Quote, error) {
		return want, nil
	}
	nonce := fakes.GetFakeNonce()
	jsonBody, err := json.Marshal(
		struct {
			Nonce []byte
		}{Nonce: nonce},
	)
	if err != nil {
		t.Error(err)
	}
	req, err := http.NewRequest("POST", "/attest", bytes.NewBuffer(jsonBody))
	req.Header.Set("X-Custom-Header", "myvalue")
	req.Header.Set("Content-Type", "application/json")

	res := httptest.NewRecorder()

	attest(res, req)
	var resQuote tpm.QuoteData
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&resQuote)
	if err != nil {
		t.Error(err)
	}
}
