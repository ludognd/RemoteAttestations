package prover

import (
	"bytes"
	"fmt"
	"github.com/google/go-cmp/cmp"
	verifierFakes "github.com/xcaliburne/RemoteAttestations/internal/verifier/tests/fakes"
	"github.com/xcaliburne/RemoteAttestations/pkg/httpClient"
	httpMocks "github.com/xcaliburne/RemoteAttestations/pkg/httpClient/tests/mocks"
	"github.com/xcaliburne/RemoteAttestations/pkg/tests"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	tpmFakes "github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/fakes"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/mocks"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
)

func TestDataProver_IsInit(t *testing.T) {
	p := DataProver{}
	var testSuite = []struct {
		name    string
		mock    mocks.MockTPM
		want    bool
		wantErr error
	}{
		{
			name: "Correct use (false)",
			mock: mocks.MockTPM{CatchIsOwned: func() (bool, error) {
				return false, nil
			}},
			want:    false,
			wantErr: nil,
		},
		{
			name: "Correct use (true)",
			mock: mocks.MockTPM{CatchIsOwned: func() (bool, error) {
				return true, nil
			}},
			want:    true,
			wantErr: nil,
		},
		{
			name: "tpm returns error",
			mock: mocks.MockTPM{CatchIsOwned: func() (bool, error) {
				return false, fmt.Errorf("some error")
			}},
			want:    false,
			wantErr: fmt.Errorf("some error"),
		},
	}

	for _, test := range testSuite {
		t.Run(test.name, func(t *testing.T) {
			p.TPM = &test.mock
			got, gotErr := p.isInit()
			if test.wantErr == nil && gotErr != nil {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
			} else if test.wantErr != nil && gotErr == nil {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
			}
			if !cmp.Equal(got, test.want) {
				t.Errorf(tests.Failure(t, got, test.want, ""))
			}
		})
	}

}

func TestDataProver_Attest(t *testing.T) {
	p := DataProver{}
	var testSuite = []struct {
		name    string
		mock    mocks.MockTPM
		input   []byte
		want    tpm.Quote
		wantErr error
	}{
		{
			name: "Correct use",
			mock: mocks.MockTPM{
				CatchQuote: func(ak tpm.AttestationKey, nonce []byte, pcrIds []int) (tpm.Quote, error) {
					return tpmFakes.GetFakeQuote(), nil
				},
			},
			input:   verifierFakes.GetFakeNonce(),
			want:    tpmFakes.GetFakeQuote(),
			wantErr: nil,
		},
		{
			name: "tpm returns an error",
			mock: mocks.MockTPM{
				CatchQuote: func(ak tpm.AttestationKey, nonce []byte, pcrIds []int) (tpm.Quote, error) {
					return nil, fmt.Errorf("some error")
				},
			},
			input:   verifierFakes.GetFakeNonce(),
			want:    nil,
			wantErr: fmt.Errorf("some error"),
		},
	}

	for _, test := range testSuite {
		t.Run(test.name, func(t *testing.T) {
			p.TPM = &test.mock
			got, gotErr := p.Attest(test.input)
			if test.wantErr == nil && gotErr != nil {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
			} else if test.wantErr != nil && gotErr == nil {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
			}
			if !cmp.Equal(got, test.want) {
				t.Errorf(tests.Failure(t, got, test.want, ""))
			}
		})
	}
}

//func TestProver_load(t *testing.T) {
//mockTPM := &mocks.MockTPM{}
//mockEK := mocks.MockEndorsementKey{}
//mockAk := mocks.MockAttestationKey{}
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
//}

func TestDataProver_Register(t *testing.T) {
	u := &url.URL{}
	parsedUrl, _ := u.Parse("http://127.0.0.1")
	conf := &Config{
		Name:            "test",
		AKFile:          "ak.json",
		OwnerPassword:   "test",
		UserPassword:    "test",
		VerifierAddress: parsedUrl,
	}
	var testSuite = []struct {
		name    string
		mock    httpMocks.MockHttpClient
		input   DataProver
		wantErr error
	}{
		{
			name: "Correct use",
			mock: httpMocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						Status:     "",
						StatusCode: 200,
						Body:       ioutil.NopCloser(bytes.NewReader([]byte{})), //empty body != nil
					}, nil
				},
			},
			input: DataProver{
				Config: conf,
				AK:     tpmFakes.GetFakeAttestationKeyValid(),
				EK:     tpmFakes.GetFakeEndorsementKeyValid(),
			},
			wantErr: nil,
		},
		{
			name: "Server returns error",
			mock: httpMocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return nil, fmt.Errorf("some error")
				},
			},
			input: DataProver{
				Config: conf,
				AK:     tpmFakes.GetFakeAttestationKeyValid(),
				EK:     tpmFakes.GetFakeEndorsementKeyValid(),
			},
			wantErr: fmt.Errorf("some error"),
		},
		{
			name: "Server does not return status OK (200)",
			mock: httpMocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						Status:     "",
						StatusCode: 500,
						Body:       ioutil.NopCloser(bytes.NewReader([]byte{})), //empty body != nil
					}, nil
				},
			},
			input: DataProver{
				Config: conf,
				AK:     tpmFakes.GetFakeAttestationKeyValid(),
				EK:     tpmFakes.GetFakeEndorsementKeyValid(),
			},
			wantErr: fmt.Errorf("some error"),
		},
		{
			name: "AK is nil",
			mock: httpMocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						Status:     "",
						StatusCode: 200,
						Body:       ioutil.NopCloser(bytes.NewReader([]byte{})), //empty body != nil
					}, nil
				},
			},
			input: DataProver{
				Config: conf,
				AK:     nil,
				EK:     tpmFakes.GetFakeEndorsementKeyValid(),
			},
			wantErr: fmt.Errorf("some error"),
		},
		{
			name: "EK is nil",
			mock: httpMocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						Status:     "",
						StatusCode: 200,
						Body:       ioutil.NopCloser(bytes.NewReader([]byte{})), //empty body != nil
					}, nil
				},
			},
			input: DataProver{
				Config: conf,
				AK:     tpmFakes.GetFakeAttestationKeyValid(),
				EK:     nil,
			},
			wantErr: fmt.Errorf("some error"),
		},
		{
			name: "config is nil",
			mock: httpMocks.MockHttpClient{
				CatchPost: func(url string, contentType string, body []byte) (*http.Response, error) {
					return &http.Response{
						Status:     "",
						StatusCode: 200,
						Body:       ioutil.NopCloser(bytes.NewReader([]byte{})), //empty body != nil
					}, nil
				},
			},
			input: DataProver{
				Config: nil,
				AK:     tpmFakes.GetFakeAttestationKeyValid(),
				EK:     tpmFakes.GetFakeEndorsementKeyValid(),
			},
			wantErr: fmt.Errorf("some error"),
		},
	}

	for _, test := range testSuite {
		t.Run(test.name, func(t *testing.T) {
			httpClient.Client = &test.mock
			gotErr := test.input.Register("127.0.0.1", "8080")
			if test.wantErr == nil && gotErr != nil {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
			} else if test.wantErr != nil && gotErr == nil {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
			}
		})
	}
}
