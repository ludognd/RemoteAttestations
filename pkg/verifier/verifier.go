package verifier

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/pkg/httpClient"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"net/http"
)

type Verifier interface {
	InitParams() InitializationParams
	RegisterNewEK(p *Prover) error
	RegisterNewAK(p *Prover) error
	AttestationRequest(nonce []byte, url string) (tpm.Quote, error)
	HasProvers() bool
	StartAttestations()
	GetChallenge() ([]byte, error)
}

type DataVerifier struct {
	Config    *Config
	ProversEK map[string]*Prover
	ProversAK map[string]*Prover
}

var _ Verifier = (*DataVerifier)(nil) // Verify that *tspiTPM implements TPM.

func NewVerifier(config *Config) *DataVerifier {
	return &DataVerifier{Config: config, ProversEK: map[string]*Prover{}, ProversAK: map[string]*Prover{}}
}

func (v *DataVerifier) InitParams() InitializationParams {
	return v.Config.Init
}

func (v *DataVerifier) GetProverEK(k *rsa.PublicKey) (*Prover, error) {
	key := fmt.Sprintf("%v:%v", k.N.String(), k.E)
	if p, ok := v.ProversEK[key]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("prover not found")
}

func (v *DataVerifier) PutProverEK(p *Prover) error {
	if p.EK == nil {
		return fmt.Errorf("endorsement key not set\n")
	}
	key := fmt.Sprintf("%v:%v", p.EK.PublicKey().N.String(), p.EK.PublicKey().E)
	if _, ok := v.ProversEK[key]; ok {
		return fmt.Errorf("endorsement key already set\n")
	}
	v.ProversEK[key] = p
	return nil
}

func (v *DataVerifier) GetProverAK(k *rsa.PublicKey) (*Prover, error) {
	key := fmt.Sprintf("%v:%v", k.N.String(), k.E)
	if p, ok := v.ProversAK[key]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("prover not found")
}

func (v *DataVerifier) PutProverAK(p *Prover) error {
	if p.AK == nil {
		return fmt.Errorf("attestation key not set\n")
	}
	key := fmt.Sprintf("%v:%v", p.AK.PublicKey().N.String(), p.AK.PublicKey().E)
	if _, ok := v.ProversAK[key]; ok {
		return fmt.Errorf("attestation key already set\n")
	}
	v.ProversAK[key] = p
	return nil
}

func (v *DataVerifier) RegisterNewEK(p *Prover) error {
	if err := p.EK.VerifyEKCert(); err != nil {
		return fmt.Errorf("error verifying EK Certificate: %v", err)
	}
	err := v.PutProverEK(p)
	if err != nil {
		return fmt.Errorf("error storing new EK: %v", err)
	}
	return nil
}

func (v *DataVerifier) RegisterNewAK(p *Prover) error {
	newP, err := v.GetProverEK(p.EK.PublicKey())
	if err != nil {
		return fmt.Errorf("error retrieving prover: %v", err)
	}
	newP.AK = p.AK
	err = v.PutProverAK(newP)
	if err != nil {
		return fmt.Errorf("error storing new EK: %v", err)
	}
	return nil
}

func (v *DataVerifier) HasProvers() bool {
	return len(v.ProversAK) != 0
}

func (v *DataVerifier) StartAttestations() {
	log.Info("Starting attestations")
	for _, p := range v.ProversAK {
		nonce, err := v.GetChallenge()
		if err != nil {
			log.Errorf("error computing challenge: %v", err)
		}
		url := fmt.Sprintf("http://%s:%s/attest", p.Endpoint, p.Port)
		//_, err = v.AttestationRequest(nonce, url)
		attestation, err := v.AttestationRequest(nonce, url)
		if err != nil {
			log.Fatalf("error attesting %v(%v) on URL %v:  %v", p.Name, p.Endpoint, url, err)
		}
		err = attestation.Verify(p.AK, nonce)
		if err != nil {
			log.Errorf("%v(%v:%v): Invalide Quote: %v", p.Name, p.Endpoint, p.Port, err)
		} else {
			log.Infof("%v(%v:%v): Valid Quote", p.Name, p.Endpoint, p.Port)
		}
	}
}

func (v *DataVerifier) AttestationRequest(nonce []byte, url string) (tpm.Quote, error) {
	body := struct{ Nonce []byte }{Nonce: nonce}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	r, err := httpClient.Client.Post(url, "application/json", jsonBody)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, errors.New(r.Status)
	}
	var attestation tpm.Quote
	attestation, err = tpm.DeserializeQuote(r.Body)
	if err != nil {
		return nil, err
	}
	err = r.Body.Close()
	if err != nil {
		return nil, err
	}
	return attestation, nil
}

func (v *DataVerifier) GetChallenge() ([]byte, error) {
	nonce := [8]byte{}
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, fmt.Errorf("error reading random nonce: %v", err)
	}
	return nonce[:], nil
}
