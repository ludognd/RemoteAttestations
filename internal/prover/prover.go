package prover

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"net/http"
)

type Prover interface {
	Register(restIP, restPort string) error
	Attest(nonce []byte) (tpm.Quote, error)
}

type DataProver struct {
	Config *Config
	TPM    tpm.TPM
	AK     tpm.AttestationKey
	EK     tpm.EndorsementKey
}

var _ Prover = (*DataProver)(nil)

func NewProver(config *Config) (*DataProver, error) {
	var p DataProver
	var err error
	t, err := tpm.Open()
	if err != nil {
		return nil, fmt.Errorf("error opening TPM: %v", err)
	}
	p.TPM, p.Config = t, config
	isInit, err := p.isInit()
	if err != nil {
		return nil, err
	}
	if !isInit {
		err = p.init()
		if err != nil {
			return nil, fmt.Errorf("error initializing prover: %v", err)
		}
	}
	err = p.load()
	if err != nil {
		return nil, fmt.Errorf("error loading prover: %v", err)
	}
	return &p, nil
}

func (p *DataProver) isInit() (bool, error) {
	owned, err := p.TPM.IsOwned()
	if err != nil {
		return false, err
	}
	return owned, nil
}

func (p *DataProver) init() error {
	var err error
	err = p.TPM.TakeOwnership(p.Config.OwnerPassword, p.Config.UserPassword)
	if err != nil {
		return fmt.Errorf("error taking ownership: %v", err)
	}
	ak, err := p.TPM.CreateAK()
	if err != nil {
		return fmt.Errorf("error while creating ak: %v", err)
	}
	err = ak.Save(p.Config.AKFile)
	log.Info("saved ak in ", p.Config.AKFile)
	if err != nil {
		return fmt.Errorf("error saving ak: %v", err)
	}
	return nil
}

func (p *DataProver) load() error {
	err := p.TPM.ProveOwnership(p.Config.OwnerPassword)
	if err != nil {
		return fmt.Errorf("error proving ownership: %v", err)
	}
	err = p.TPM.ProveUsership(p.Config.UserPassword)
	if err != nil {
		return fmt.Errorf("error proving usership: %v", err)
	}
	ek, err := p.TPM.GetEK()
	if err != nil {
		return fmt.Errorf("error getting EK: %v", err)
	}
	ak, err := tpm.LoadAK(p.Config.AKFile)
	if err != nil {
		return fmt.Errorf("error loading AK: %v", err)
	}
	p.AK, p.EK = ak, ek
	return nil
}

func (p *DataProver) Register(restIP, restPort string) error {
	err := p.registerEK(restIP, restPort)
	if err != nil {
		return err
	}
	return p.registerAK()
}

func (p *DataProver) registerEK(restIP, restPort string) error {
	restIP = "10.42.0.152" //TODO: fix hardcoded
	queryURL := p.Config.VerifierAddress
	queryURL.Path = "registerNewEK"
	body := struct {
		Name     string
		Endpoint string
		Port     string
		EK       tpm.EndorsementKey
	}{
		Name:     p.Config.Name,
		Endpoint: restIP,
		Port:     restPort,
		EK:       p.EK,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("error while marshaling body: %v", err)
	}
	r, err := http.Post(queryURL.String(), "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error post query: %v", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("an error occured during query: %v", r.Status)
	}
	return nil
}

func (p *DataProver) registerAK() error {
	queryURL := p.Config.VerifierAddress
	queryURL.Path = "registerNewAK"
	body := struct {
		EK tpm.EndorsementKey
		AK tpm.AttestationKey
	}{p.EK, p.AK}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("error while marshaling body: %v", err)
	}
	r, err := http.Post(queryURL.String(), "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error post query: %v", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("an error occured during query: %v", r.Status)
	}
	return nil
}

func (p *DataProver) Attest(nonce []byte) (tpm.Quote, error) {
	quote, err := p.TPM.Quote(p.AK, nonce, tpm.All_pcrs[:])
	if err != nil {
		return nil, fmt.Errorf("error while quoting: %v", err)
	}
	//fmt.Printf("quote: %+v\n", quote)
	return quote, nil
}
