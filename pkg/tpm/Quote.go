package tpm

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
)

type Quote interface {
	Verify(ak AttestationKey, nonce []byte) error
	VerifyPCRs(pcrs []PCR) error
}

type QuoteData struct {
	Raw       []byte
	Parsed    ParsedQuote
	Signature []byte
}

type ParsedQuote struct {
	Version [4]byte  // This MUST be 1.1.0.0
	Fixed   [4]byte  // This SHALL always be the string ‘QUOT’
	Digest  [20]byte // PCR Composite Hash
	Nonce   [20]byte // Nonce Hash
}

var _ Quote = (*QuoteData)(nil) // Verify that *QuoteData implements Quote.

var (
	DeserializeQuote = func(r io.Reader) (Quote, error) {
		q := &QuoteData{}
		decoder := json.NewDecoder(r)
		err := decoder.Decode(q)
		if err != nil {
			return nil, err
		}
		return q, nil
	}
	SerializeQuote = func(q Quote) ([]byte, error) {
		return json.Marshal(q)
	}
)

func (q *QuoteData) Verify(ak AttestationKey, nonce []byte) error {
	quoteDigest := sha1.Sum(q.Raw)
	//First check signature
	if err := rsa.VerifyPKCS1v15(ak.PublicKey(), crypto.SHA1, quoteDigest[:], q.Signature); err != nil {
		return fmt.Errorf("invalid signature: %v", err)
	}
	//Check nonce
	if q.Parsed.Nonce != sha1.Sum(nonce) {
		return fmt.Errorf("invalid nonce")
	}
	//Check object received from tspiTPM
	if string(q.Parsed.Fixed[:]) != "QUOT" {
		return fmt.Errorf("expected QUOT object got %s", q.Parsed.Fixed)
	}
	return nil
}

func (q *QuoteData) VerifyPCRs(pcrs []PCR) error {
	//Check pcr values
	composite, err := pcrsToComposite(pcrs)
	if err != nil {
		return fmt.Errorf("creating composite: %v", err)
	}
	if q.Parsed.Digest != sha1.Sum(composite) {
		return fmt.Errorf("PCRs don't match ParsedQuote: %v", err)
	}
	return nil
}

func (q *QuoteData) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Raw       []byte
		Parsed    ParsedQuote
		Signature []byte
	}{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if len(aux.Raw) == 0 ||
		len(aux.Signature) == 0 ||
		bytes.Equal(aux.Parsed.Nonce[:], make([]byte, cap(aux.Parsed.Nonce))) ||
		bytes.Equal(aux.Parsed.Digest[:], make([]byte, cap(aux.Parsed.Digest))) ||
		bytes.Equal(aux.Parsed.Fixed[:], make([]byte, cap(aux.Parsed.Fixed))) ||
		bytes.Equal(aux.Parsed.Version[:], make([]byte, cap(aux.Parsed.Version))) {
		return fmt.Errorf("missing required fields")
	}
	q.Raw, q.Parsed, q.Signature = aux.Raw, aux.Parsed, aux.Signature
	return nil
}
