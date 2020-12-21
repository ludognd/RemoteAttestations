package RestServer

import (
	"encoding/json"
	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/internal/prover"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier/tests/fakes"
	"github.com/xcaliburne/RemoteAttestations/pkg/httpClient"
	"github.com/xcaliburne/RemoteAttestations/pkg/tests"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm/tests/mocks"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

var r *RestServer
var p = &prover.Prover{
	Config: &prover.Config{
		Name:          "test",
		AKFile:        "ak.json",
		OwnerPassword: "tpmOwnerPassword",
		UserPassword:  "tpmUserPassword",
		VerifierAddress: &url.URL{
			Scheme:      "http",
			Opaque:      "",
			User:        nil,
			Host:        "127.0.0.1",
			Path:        "",
			RawPath:     "",
			ForceQuery:  false,
			RawQuery:    "",
			Fragment:    "",
			RawFragment: "",
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
	var want tpm.Quote
	var wantStatus, gotStatus int
	var got *tpm.QuoteData
	var wantErr, gotErr error

	mockTPM := mocks.MockTPM{}
	p.TPM = &mockTPM

	r.Run()
	defer func() {
		if err := r.Stop(); err != nil {
			log.Errorf("error closing server: %v", err)
		}
	}()
	time.Sleep(1 * time.Second) //wait for server to be ready

	want, wantErr = mocks.GetFakeQuote(), nil
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
	//Test valid query
	req, gotErr := httpClient.Client.Post("http://"+r.server.Addr+"/attest", "application/json", jsonBody)
	if gotErr != wantErr {
		t.Error(tests.Failure(t, gotErr, wantErr, ""))
		t.Skip()
	}
	decoder := json.NewDecoder(req.Body)
	err = decoder.Decode(&got)
	if err != nil {
		t.Error(err)
	}
	if !cmp.Equal(got, want) {
		t.Error(tests.Failure(t, got, want, ""))
	}

	//Test query without nonce
	want, wantErr, wantStatus = nil, nil, http.StatusInternalServerError
	req, gotErr = httpClient.Client.Post("http://"+r.server.Addr+"/attest", "application/json", []byte("{}"))
	if gotErr != wantErr {
		t.Error(tests.Failure(t, gotErr, wantErr, ""))
		t.Skip()
	}
	gotStatus = req.StatusCode
	if gotStatus != wantStatus {
		t.Error(tests.Failure(t, gotStatus, wantStatus, ""))
	}
}
