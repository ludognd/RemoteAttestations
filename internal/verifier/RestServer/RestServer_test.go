package RestServer

import (
	"encoding/json"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier/tests/mocks"
	"github.com/xcaliburne/RemoteAttestations/pkg/httpClient"
	"github.com/xcaliburne/RemoteAttestations/pkg/tests"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/fakes"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var r *RestServer
var v = &mocks.MockVerifier{}
var config = &Config{
	Address: net.IP{127, 0, 0, 1},
	Port:    "8080",
}

func init() {
	//disable server logs
	log.SetOutput(ioutil.Discard)
	var err error
	r, err = NewServer(config, v)
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
		v: v,
	}, nil
	got, gotErr = NewServer(config, v)
	if gotErr != wantErr {
		t.Error(tests.Failure(t, gotErr, wantErr, ""))
	}
	if !cmp.Equal(got.config, want.config) {
		t.Error(tests.Failure(t, *got.config, *want.config, ""))
	}
	if !cmp.Equal(got.v, want.v) {
		t.Error(tests.Failure(t, got.v, want.v, ""))
	}
}

func TestRestServer_registerNewEK(t *testing.T) {
	jsonFormat := "{\"Name\":\"%s\",\"Endpoint\":\"%s\",\"Port\":\"%s\",\"EK\":%s}"
	jsonEK, err := json.Marshal(fakes.GetFakeEndorsementKeyValid())
	if err != nil {
		t.Fatalf("unable to marshal json: %v", err)
	}

	var testSuite = []struct {
		name    string
		input   string
		mock    mocks.MockVerifier
		want    int
		wantErr error
	}{
		{
			name:    "correct query",
			input:   fmt.Sprintf(jsonFormat, "test", "127.0.0.1", "8080", string(jsonEK)),
			mock:    mocks.MockVerifier{CatchRegisterNewEK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusOK,
			wantErr: nil,
		},
		{
			name:    "query without name",
			input:   fmt.Sprintf(jsonFormat, "", "127.0.0.1", "8080", string(jsonEK)),
			mock:    mocks.MockVerifier{CatchRegisterNewEK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusBadRequest,
			wantErr: nil,
		},
		{
			name:    "query without endpoint",
			input:   fmt.Sprintf(jsonFormat, "test", "", "8080", string(jsonEK)),
			mock:    mocks.MockVerifier{CatchRegisterNewEK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusBadRequest,
			wantErr: nil,
		},
		{
			name:    "query without port",
			input:   fmt.Sprintf(jsonFormat, "test", "127.0.0.1", "", string(jsonEK)),
			mock:    mocks.MockVerifier{CatchRegisterNewEK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusBadRequest,
			wantErr: nil,
		},
		{
			name:    "query without EK",
			input:   fmt.Sprintf(jsonFormat, "test", "127.0.0.1", "8080", "\"\""),
			mock:    mocks.MockVerifier{CatchRegisterNewEK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusBadRequest,
			wantErr: nil,
		},
		{
			name:    "query with invalid json",
			input:   fmt.Sprintf(jsonFormat, "\"{{{", "", "", ""),
			mock:    mocks.MockVerifier{CatchRegisterNewEK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusBadRequest,
			wantErr: nil,
		},
		{
			name:    "query with invalid EK",
			input:   fmt.Sprintf(jsonFormat, "test", "127.0.0.1", "8080", string(jsonEK)),
			mock:    mocks.MockVerifier{CatchRegisterNewEK: func(p *verifier.Prover) error { return fmt.Errorf("some error") }},
			want:    http.StatusInternalServerError,
			wantErr: nil,
		},
	}
	testServer := httptest.NewServer(http.HandlerFunc(r.registerNewEK))
	defer testServer.Close()

	for _, test := range testSuite {
		t.Run(test.name, func(t *testing.T) {
			r.v = &test.mock
			req, gotErr := httpClient.Client.Post(testServer.URL, "application/json", []byte(test.input))
			if gotErr != test.wantErr {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
				t.Skip()
			}
			got := req.StatusCode
			if !cmp.Equal(got, test.want) {
				t.Error(tests.Failure(t, got, test.want, ""))
			}
		})
	}
}

func TestRestServer_registerNewAK(t *testing.T) {
	jsonFormat := "{\"EK\": %s,\"AK\": %s}"
	jsonEK, err := json.Marshal(fakes.GetFakeEndorsementKeyValid())
	if err != nil {
		t.Fatalf("unable to marshal json: %v", err)
	}
	jsonAK, err := json.Marshal(fakes.GetFakeAttestationKeyValid())
	if err != nil {
		t.Fatalf("unable to marshal json: %v", err)
	}

	var testSuite = []struct {
		name    string
		input   string
		mock    mocks.MockVerifier
		want    int
		wantErr error
	}{
		{
			name:    "correct query",
			input:   fmt.Sprintf(jsonFormat, string(jsonEK), string(jsonAK)),
			mock:    mocks.MockVerifier{CatchRegisterNewAK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusOK,
			wantErr: nil,
		},
		{
			name:    "query without EK",
			input:   fmt.Sprintf(jsonFormat, "{}", string(jsonAK)),
			mock:    mocks.MockVerifier{CatchRegisterNewAK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusBadRequest,
			wantErr: nil,
		},
		{
			name:    "query without AK",
			input:   fmt.Sprintf(jsonFormat, string(jsonEK), "{}"),
			mock:    mocks.MockVerifier{CatchRegisterNewAK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusBadRequest,
			wantErr: nil,
		},
		{
			name:    "query with internal error",
			input:   fmt.Sprintf(jsonFormat, string(jsonEK), string(jsonAK)),
			mock:    mocks.MockVerifier{CatchRegisterNewAK: func(p *verifier.Prover) error { return fmt.Errorf("some error") }},
			want:    http.StatusInternalServerError,
			wantErr: nil,
		},
		{
			name:    "query with invalid json",
			input:   fmt.Sprintf(jsonFormat, "{{{{", "{}"),
			mock:    mocks.MockVerifier{CatchRegisterNewEK: func(p *verifier.Prover) error { return nil }},
			want:    http.StatusBadRequest,
			wantErr: nil,
		},
	}

	testServer := httptest.NewServer(http.HandlerFunc(r.registerNewAK))
	defer testServer.Close()
	for _, test := range testSuite {
		t.Run(test.name, func(t *testing.T) {
			r.v = &test.mock
			req, gotErr := httpClient.Client.Post(testServer.URL, "application/json", []byte(test.input))
			if gotErr != test.wantErr {
				t.Error(tests.Failure(t, gotErr, test.wantErr, ""))
				t.Skip()
			}
			got := req.StatusCode
			if !cmp.Equal(got, test.want) {
				t.Error(tests.Failure(t, got, test.want, ""))
			}
		})
	}
}
