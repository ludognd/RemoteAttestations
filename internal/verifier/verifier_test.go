package verifier_test

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier/tests/fakes"
	"github.com/xcaliburne/RemoteAttestations/pkg/httpClient"
	"github.com/xcaliburne/RemoteAttestations/pkg/httpClient/tests/mocks"
	"github.com/xcaliburne/RemoteAttestations/pkg/tests"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	tpmFakes "github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/fakes"
	tpmMocks "github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/mocks"
	"io/ioutil"
	"net/http"
	"testing"
)

var config = &verifier.Config{
	Init: verifier.InitializationParams{
		OwnerPassword: "",
		UserPassword:  "",
	},
}

func TestNewVerifier(t *testing.T) {
	want := &verifier.DataVerifier{
		Config:    config,
		ProversEK: map[string]*verifier.Prover{},
		ProversAK: map[string]*verifier.Prover{},
	}

	got := verifier.NewVerifier(config)
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

func TestDataVerifier_InitParams(t *testing.T) {
	v := verifier.NewVerifier(config)
	want := v.Config.Init
	got := v.InitParams()
	if !cmp.Equal(got, want) {
		t.Error(tests.Failure(t, got, want, ""))
	}
}

func TestDataVerifier_AttestationRequest(t *testing.T) {
	v := verifier.NewVerifier(config)
	jsonQuote, err := json.Marshal(tpmFakes.GetFakeQuote())
	if err != nil {
		t.Fatalf("unable to marshal quote: %v", err)
	}
	var testSuite = []struct {
		name    string
		input   []byte
		mock    mocks.MockHttpClient
		want    tpm.Quote
		wantErr error
	}{
		{
			name:  "correct use",
			input: fakes.GetFakeNonce(),
			mock: mocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       ioutil.NopCloser(bytes.NewReader(jsonQuote)),
					}, nil
				},
			},
			want:    tpmFakes.GetFakeQuote(),
			wantErr: nil,
		},
		{
			name:  "invalid nonce",
			input: []byte(""),
			mock: mocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       ioutil.NopCloser(bytes.NewReader(jsonQuote)),
					}, nil
				},
			},
			want:    nil,
			wantErr: fmt.Errorf("some error"),
		},
		{
			name:  "error occurred during communication with server",
			input: fakes.GetFakeNonce(),
			mock: mocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return nil, fmt.Errorf("some error")
				},
			},
			want:    nil,
			wantErr: fmt.Errorf("some error"),
		},
		{
			name:  "server returns error",
			input: fakes.GetFakeNonce(),
			mock: mocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Body:       ioutil.NopCloser(bytes.NewReader([]byte("bad request"))),
					}, nil
				},
			},
			want:    nil,
			wantErr: fmt.Errorf("some error"),
		},
		{
			name:  "server returns bad json",
			input: []byte(""),
			mock: mocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       ioutil.NopCloser(bytes.NewReader([]byte("{some bad json"))),
					}, nil
				},
			},
			want:    nil,
			wantErr: fmt.Errorf("some error"),
		},
		{
			name:  "server returns valid json but not a quote",
			input: fakes.GetFakeNonce(),
			mock: mocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       ioutil.NopCloser(bytes.NewReader([]byte("{\"json\": \"not a quote json\"}"))),
					}, nil
				},
			},
			want:    nil,
			wantErr: fmt.Errorf("some error"),
		},
	}

	for _, test := range testSuite {
		t.Run(test.name, func(t *testing.T) {
			httpClient.Client = &test.mock
			got, gotErr := v.AttestationRequest(test.input, "127.0.0.1")
			if test.wantErr == nil && gotErr != nil {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
			} else if test.wantErr != nil && gotErr == nil {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
			}
			if !cmp.Equal(got, test.want) {
				t.Error(tests.Failure(t, got, test.want, ""))
			}
		})
	}
}

func TestDataVerifier_RegisterNewEK(t *testing.T) {
	v := verifier.NewVerifier(config)
	pkValid := tpmFakes.GetFakeEndorsementKeyValid().PublicKey()
	var testSuite = []struct {
		name  string
		input *verifier.Prover
		want  error
	}{
		{
			name: "correct use",
			input: &verifier.Prover{
				Name:     "test",
				Endpoint: "0.0.0.0",
				Port:     "80",
				EK: &tpmMocks.MockEndorsementKey{
					CatchVerifyEKCert: func() error {
						return nil
					},
					CatchPublicKey: func() *rsa.PublicKey {
						return pkValid
					},
				},
				AK: nil,
			},
			want: nil,
		},
		{
			name: "reinsert same key",
			input: &verifier.Prover{
				Name:     "test",
				Endpoint: "0.0.0.0",
				Port:     "80",
				EK: &tpmMocks.MockEndorsementKey{
					CatchVerifyEKCert: func() error {
						return nil
					},
					CatchPublicKey: func() *rsa.PublicKey {
						return pkValid
					},
				},
				AK: nil,
			},
			want: fmt.Errorf("some error"),
		},
		{
			name: "EK certificate is invalid",
			input: &verifier.Prover{
				Name:     "test",
				Endpoint: "0.0.0.0",
				Port:     "80",
				EK: &tpmMocks.MockEndorsementKey{
					CatchVerifyEKCert: func() error {
						return fmt.Errorf("some error")
					},
				},
				AK: nil,
			},
			want: fmt.Errorf("some error"),
		},
		{
			name: "EK is nil",
			input: &verifier.Prover{
				Name:     "",
				Endpoint: "",
				Port:     "",
				EK:       nil,
				AK:       nil,
			},
			want: fmt.Errorf("some error"),
		},
	}

	for _, test := range testSuite {
		t.Run(test.name, func(t *testing.T) {
			got := v.RegisterNewEK(test.input)
			if test.want == nil && got != nil {
				t.Error(tests.Failure(t, got, test.want, ""))
			} else if test.want != nil && got == nil {
				t.Error(tests.Failure(t, got, test.want, ""))
			}
		})
	}
}

func TestDataVerifier_RegisterNewAK(t *testing.T) {
	v := verifier.NewVerifier(config)
	pkValid := tpmFakes.GetFakeEndorsementKeyValid().PublicKey()
	p := &verifier.Prover{
		Name:     "test",
		Endpoint: "0.0.0.0",
		Port:     "80",
		EK: &tpmMocks.MockEndorsementKey{
			CatchVerifyEKCert: func() error {
				return nil
			},
			CatchPublicKey: func() *rsa.PublicKey {
				return pkValid
			},
		},
		AK: &tpmMocks.MockAttestationKey{
			CatchPublicKey: func() *rsa.PublicKey {
				return pkValid
			},
		},
	}
	var testSuite = []struct {
		name    string
		init    func()
		cleanup func()
		input   *verifier.Prover
		want    error
	}{
		{
			name:  "correct use",
			init:  func() { v.RegisterNewEK(p) },
			cleanup: func() { v.ProversEK, v.ProversAK = map[string]*verifier.Prover{}, map[string]*verifier.Prover{} },
			input: p,
			want:  nil,
		},
		{
			name:  "reinsert same key",
			init:  func() {
				v.RegisterNewEK(p)
				v.RegisterNewAK(p)
			},
			cleanup: func() { v.ProversEK, v.ProversAK = map[string]*verifier.Prover{}, map[string]*verifier.Prover{} },
			input: p,
			want:  fmt.Errorf("some error"),
		},
		{
			name:  "unable to retrieve prover",
			init:  func() {},
			cleanup: func() {},
			input: p,
			want:  fmt.Errorf("some error"),
		},
		{
			name: "EK is nil",
			init: func() {v.RegisterNewEK(p)},
			cleanup: func() { v.ProversEK, v.ProversAK = map[string]*verifier.Prover{}, map[string]*verifier.Prover{} },
			input: &verifier.Prover{
				Name:     "test",
				Endpoint: "0.0.0.0",
				Port:     "80",
				EK:       nil,
				AK: &tpmMocks.MockAttestationKey{
					CatchPublicKey: func() *rsa.PublicKey {
						return pkValid
					},
				},
			},
			want: fmt.Errorf("some error"),
		},
		{
			name: "AK is nil",
			init: func() {v.RegisterNewEK(p)},
			cleanup: func() { v.ProversEK, v.ProversAK = map[string]*verifier.Prover{}, map[string]*verifier.Prover{} },
			input: &verifier.Prover{
				Name:     "test",
				Endpoint: "0.0.0.0",
				Port:     "80",
				EK: &tpmMocks.MockEndorsementKey{
					CatchVerifyEKCert: func() error {
						return nil
					},
					CatchPublicKey: func() *rsa.PublicKey {
						return pkValid
					},
				},
				AK: nil,
			},
			want: fmt.Errorf("some error"),
		},
	}

	for _, test := range testSuite {
		t.Run(test.name, func(t *testing.T) {
			test.init()
			got := v.RegisterNewAK(test.input)
			if test.want == nil && got != nil {
				t.Error(tests.Failure(t, got, test.want, ""))
			} else if test.want != nil && got == nil {
				t.Error(tests.Failure(t, got, test.want, ""))
			}
		})
	}
}
