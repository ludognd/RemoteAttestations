package tpm

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-tspi/verification"
)

type EndorsementKey interface {
	VerifyEKCert() error
	PublicKey() *rsa.PublicKey
	Certificate() *x509.Certificate
}

type EndorsementKeyData struct {
	PK *rsa.PublicKey
	C  *x509.Certificate
}

var _ EndorsementKey = (*EndorsementKeyData)(nil) // Verify that *EndorsementKeyData implements EndorsementKey.

func (ek *EndorsementKeyData) VerifyEKCert() error {
	err := verification.VerifyEKCert(ek.C.Raw)
	if !x509.IsFatal(err) {
		return nil
	}
	return err
}

func (ek *EndorsementKeyData) PublicKey() *rsa.PublicKey {
	return ek.PK
}
func (ek *EndorsementKeyData) Certificate() *x509.Certificate {
	return ek.C
}

func (ek *EndorsementKeyData) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RawCertificate []byte `json:"certificate"`
	}{RawCertificate: ek.C.Raw})
}

func (ek *EndorsementKeyData) UnmarshalJSON(data []byte) error {
	aux := &struct {
		RawCertificate []byte `json:"certificate"`
	}{RawCertificate: []byte{}}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.RawCertificate) == 0 {
		return fmt.Errorf("missing required fields")
	}
	cert, err := parseEKCertificate(aux.RawCertificate)
	if err != nil {
		return err
	}
	ek.PK = cert.PublicKey.(*rsa.PublicKey)
	ek.C = cert
	return nil
}

// ParseEKCertificate parses a Raw DER encoded EK C B.
// Source: https://github.com/google/go-attestation/blob/master/attest/tpm.go
func parseEKCertificate(ekCert []byte) (*x509.Certificate, error) {
	var wasWrapped bool

	// TCG PC Specific Implementation section 7.3.2 specifies
	// a prefix when storing a C in NVRAM. We look
	// for and unwrap the C if its present.
	if len(ekCert) > 5 && bytes.Equal(ekCert[:3], []byte{0x10, 0x01, 0x00}) {
		certLen := int(binary.BigEndian.Uint16(ekCert[3:5]))
		if len(ekCert) < certLen+5 {
			return nil, fmt.Errorf("parsing nvram header: ekCert size %d smaller than specified cert length %d", len(ekCert), certLen)
		}
		ekCert = ekCert[5 : 5+certLen]
		wasWrapped = true
	}

	// If the cert parses fine without any changes, we are G2G.
	if c, err := x509.ParseCertificate(ekCert); err == nil {
		return c, nil
	}
	// There might be trailing nonsense in the cert, which Go
	// does not parse correctly. As ASN1 data is TLV encoded, we should
	// be able to just get the C, and then send that to Go's
	// C parser.
	var cert struct {
		Raw asn1.RawContent
	}
	if _, err := asn1.UnmarshalWithParams(ekCert, &cert, "lax"); err != nil && x509.IsFatal(err) {
		return nil, fmt.Errorf("asn1.Unmarshal() failed: %v, wasWrapped=%v", err, wasWrapped)
	}

	c, err := x509.ParseCertificate(cert.Raw)
	if err != nil && x509.IsFatal(err) {
		return nil, fmt.Errorf("x509.ParseCertificate() failed: %v", err)
	}
	return c, nil
}
