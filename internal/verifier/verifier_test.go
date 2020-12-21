package verifier_test

import (
	"errors"
	"github.com/google/go-cmp/cmp"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier/tests/fakes"
	"github.com/xcaliburne/RemoteAttestations/pkg/tests"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/mocks"
	"net/http"
	"net/http/httptest"
	"testing"
)

var v verifier.DataVerifier

func init() {
	v = verifier.DataVerifier{
		Config: &verifier.Config{Init: verifier.InitializationParams{
			OwnerPassword: "",
			UserPassword:  "",
		}},
		ProversEK: map[string]*verifier.Prover{},
		ProversAK: map[string]*verifier.Prover{},
	}
}

func TestNewVerifier(t *testing.T) {
	want := &v
	got := verifier.NewVerifier(v.Config)
	//Check if got and want are deeply equals
	if !cmp.Equal(got, want) {
		t.Errorf(tests.Failure(t, got, want, ""))
	}
	if len(got.ProversAK) != 0 {
		t.Errorf("proversEK map is not empty")
	}
	if len(got.ProversEK) != 0 {
		t.Errorf("proversEK map is not empty")
	}
}

func TestVerifier_GetInitParams(t *testing.T) {
	want := v.Config.Init
	got := v.InitParams()
	if !cmp.Equal(got, want) {
		t.Error(tests.Failure(t, got, want, ""))
	}
}

func TestVerifier_GetProverAK(t *testing.T) {
	//p := fakes.GetFakeProver(mocks.GetFakeEndorsementKeyValid, mocks.GetFakeAttestationKeyValid)
	//fmt.Println(p.AK)
	//fmt.Println(p.EK)
	//var want, got *verifier.Prover
	//var wantErr, gotErr error
	//want, wantErr = nil, errors.New("some error")
	//got, gotErr = v.GetProverAK(p.AK.PublicKey())
	//if gotErr == nil {
	//	t.Error(tests.Failure(t, gotErr, wantErr, ""))
	//}
	//if !cmp.Equal(got, want) {
	//	t.Error(tests.Failure(t, gotErr, wantErr, ""))
	//}
}

func TestVerifier_AttestationRequest(t *testing.T) {
	var wantErr, gotErr error
	fakeQuote := mocks.GetFakeQuote()
	nonce := fakes.GetFakeNonce()
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		// Send response to be tested
		json, err := tpm.SerializeQuote(fakeQuote)
		if err != nil {
			t.Error(tests.Failure(t, err, nil, ""))
		}
		_, _ = rw.Write(json)
	}))
	// Close the server when test finishes
	defer server.Close()
	want, wantErr := fakeQuote, nil
	got, gotErr := v.AttestationRequest(nonce, server.URL)
	if gotErr != nil {
		t.Error(tests.Failure(t, got, wantErr, ""))
	}
	if !cmp.Equal(got, want) {
		t.Error(tests.Failure(t, got, want, ""))
	}

	//Server returns an error
	server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		// Send response to be tested
		http.Error(rw, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}))
	// Close the server when test finishes
	defer server.Close()
	want, wantErr = nil, errors.New("some error")
	got, gotErr = v.AttestationRequest(nonce, server.URL)
	if gotErr == nil {
		t.Error(tests.Failure(t, gotErr, wantErr, ""))
	}
	if !cmp.Equal(got, want) {
		t.Error(tests.Failure(t, got, want, ""))
	}

	//Server not available error
	want, wantErr = nil, errors.New("some error")
	got, gotErr = v.AttestationRequest(nonce, "")
	if gotErr == nil {
		t.Error(tests.Failure(t, gotErr, wantErr, ""))
	}
	if !cmp.Equal(got, want) {
		t.Error(tests.Failure(t, got, want, ""))
	}

	//Server returns a bad json
	server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, _ = rw.Write([]byte("{Some: bad json,}}"))
	}))
	// Close the server when test finishes
	defer server.Close()
	want, wantErr = nil, errors.New("some error")
	got, gotErr = v.AttestationRequest(nonce, server.URL)
	if gotErr == nil {
		t.Error(tests.Failure(t, got, wantErr, ""))
	}
	if !cmp.Equal(got, want) {
		t.Error(tests.Failure(t, got, want, ""))
	}
}
