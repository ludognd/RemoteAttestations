package RestServer

import (
	"encoding/json"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/internal/prover"
	"github.com/xcaliburne/RemoteAttestations/internal/prover/tests/mocks"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier/tests/fakes"
	"github.com/xcaliburne/RemoteAttestations/pkg/httpClient"
	"github.com/xcaliburne/RemoteAttestations/pkg/tests"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	tpmFakes "github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/fakes"
	mocksTPM "github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/mocks"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

var r *RestServer
var p = &prover.DataProver{
	Config: &prover.Config{
		Name:          "test",
		AKFile:        "ak.json",
		OwnerPassword: "tpmOwnerPassword",
		UserPassword:  "tpmUserPassword",
		VerifierAddress: &url.URL{
			Scheme: "http",
			Host:   "127.0.0.1",
		},
	},
	TPM: nil,
	AK:  nil,
	EK:  nil,
}
var config = &Config{
	Address: net.IP{127, 0, 0, 1},
	Port:    "8080",
}

func init() {
	log.SetOutput(ioutil.Discard)
	var err error
	r, err = NewServer(config, p)
	if err != nil {
		panic("error creating server")
	}
}

func TestNewServer(t *testing.T) {
	var want, got *RestServer
	var wantErr, gotErr error
	want, wantErr = &RestServer{
		config: config,
		server: &http.Server{
			Addr:         net.JoinHostPort(config.Address.String(), config.Port),
			WriteTimeout: time.Second * 15,
			ReadTimeout:  time.Second * 15,
			IdleTimeout:  time.Second * 60,
			Handler:      mux.NewRouter().StrictSlash(true), // Pass our instance of gorilla/mux in.
		},
		p: p,
	}, nil
	got, gotErr = NewServer(config, p)
	if gotErr != wantErr {
		t.Error(tests.Failure(t, gotErr, wantErr, ""))
	}
	if !cmp.Equal(got.config, want.config) {
		t.Error(tests.Failure(t, *got.config, *want.config, ""))
	}
	if !cmp.Equal(got.p, want.p) {
		t.Error(tests.Failure(t, got.p, want.p, ""))
	}
}

func TestRestServer_attest(t *testing.T) {
	jsonQuote, err := json.Marshal(tpmFakes.GetFakeQuote())
	if err != nil {
		t.Fatalf("Unable to marshal quote: %v", err)
	}
	var testSuite = []struct {
		name       string
		input      string
		mock       mocks.MockProver
		want       []byte
		wantErr    error
		wantStatus int
	}{
		{
			name:       "valid query",
			input:      fmt.Sprintf("{\"Nonce\": \"%v\"}", string(fakes.GetFakeNonce())),
			mock:       mocks.MockProver{CatchAttest: func(nonce []byte) (tpm.Quote, error) { return tpmFakes.GetFakeQuote(), nil }},
			want:       jsonQuote,
			wantErr:    nil,
			wantStatus: http.StatusOK,
		},
		{
			name:       "query without nonce",
			input:      fmt.Sprintf("{\"Nonce\": \"%v\"}", ""),
			mock:       mocks.MockProver{CatchAttest: func(nonce []byte) (tpm.Quote, error) { return tpmFakes.GetFakeQuote(), nil }},
			want:       []byte{},
			wantErr:    nil,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "query with invalid json",
			input:      fmt.Sprintf("{\"Nonce\": \"%v\"}", "{{"),
			mock:       mocks.MockProver{CatchAttest: func(nonce []byte) (tpm.Quote, error) { return tpmFakes.GetFakeQuote(), nil }},
			want:       []byte{},
			wantErr:    nil,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "query with internal error",
			input:      fmt.Sprintf("{\"Nonce\": \"%v\"}", string(fakes.GetFakeNonce())),
			mock:       mocks.MockProver{CatchAttest: func(nonce []byte) (tpm.Quote, error) { return nil, fmt.Errorf("some error") }},
			want:       []byte{},
			wantErr:    nil,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:  "query with marshaling error",
			input: fmt.Sprintf("{\"Nonce\": \"%v\"}", string(fakes.GetFakeNonce())),
			mock: mocks.MockProver{CatchAttest: func(nonce []byte) (tpm.Quote, error) {
				return &mocksTPM.MockQuote{
					CatchUnmarshal: func(data []byte) error {
						return fmt.Errorf("some error")
					},
				}, nil
			}},
			want:       []byte{},
			wantErr:    nil,
			wantStatus: http.StatusInternalServerError,
		},
	}

	var gotStatus int
	var got []byte

	testServer := httptest.NewServer(http.HandlerFunc(r.attest))
	defer testServer.Close()

	for _, test := range testSuite {
		t.Run(test.name, func(t *testing.T) {
			r.p = &test.mock
			req, gotErr := httpClient.Client.Post(testServer.URL, "application/json", []byte(test.input))
			if gotErr != test.wantErr {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
			}
			got, _ = ioutil.ReadAll(req.Body)
			gotStatus = req.StatusCode
			if gotStatus != test.wantStatus {
				t.Error(tests.Failure(t, gotStatus, test.wantStatus, ""))
			}
			if len(test.want) != 0 && !cmp.Equal(got, test.want) {
				t.Error(tests.Failure(t, got, test.want, ""))
			}
		})
	}
}
