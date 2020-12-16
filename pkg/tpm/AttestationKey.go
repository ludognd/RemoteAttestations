package tpm

import (
	"bufio"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type AttestationKey interface {
	Save(filePath string) error
	PublicKey() *rsa.PublicKey
	Blob() []byte
}

type AttestationKeyData struct {
	PK *rsa.PublicKey
	B  []byte
}

type attestationKeyData struct {
	PublicKey *rsa.PublicKey
	Blob      []byte
}

var _ AttestationKey = (*AttestationKeyData)(nil) // Verify that *AttestationKeyData implements AttestationKey.

func LoadAK(filePath string) (*AttestationKeyData, error) {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading attestation key file: %v", err)
	}
	var ak AttestationKeyData
	err = json.Unmarshal(file, &ak)
	if err != nil {
		return nil, err
	}
	return &ak, nil
}

func (ak *AttestationKeyData) Save(filePath string) error {
	akJson, err := json.Marshal(ak)
	if err != nil {
		return fmt.Errorf("error marshaling attestation key: %v", err)
	}
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return fmt.Errorf("error opening attestation key file: %v", err)
	}
	defer file.Close()
	w := bufio.NewWriter(file)
	_, err = w.Write(akJson)
	if err != nil {
		return fmt.Errorf("error writing attestation key: %v", err)
	}
	err = w.Flush()
	if err != nil {
		return fmt.Errorf("error writing attestation key: %v", err)
	}
	return nil
}

func (ak *AttestationKeyData) PublicKey() *rsa.PublicKey {
	return ak.PK
}

func (ak *AttestationKeyData) Blob() []byte {
	return ak.B
}

func (ak *AttestationKeyData) MarshalJSON() ([]byte, error) {
	return json.Marshal(&attestationKeyData{PublicKey: ak.PublicKey(), Blob: ak.Blob()})
}

func (ak *AttestationKeyData) UnmarshalJSON(data []byte) error {
	aux := &attestationKeyData{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	ak.PK, ak.B = aux.PublicKey, aux.Blob
	return nil
}
