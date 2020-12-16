package mocks

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/google/certificate-transparency-go/x509"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"math/big"
)

type MockEndorsementKey struct {
	CatchVerifyEKCert func() error
	CatchPublicKey    func() *rsa.PublicKey
	CatchCertificate  func() *x509.Certificate
	data              tpm.EndorsementKeyData
}

var _ tpm.EndorsementKey = (*MockEndorsementKey)(nil) // Verify that *MockEndorsementKey implements EndorsementKey.

func (ek *MockEndorsementKey) VerifyEKCert() error {
	//default behavior
	if ek.CatchVerifyEKCert == nil {
		return nil
	}
	return ek.CatchVerifyEKCert()
}

func (ek *MockEndorsementKey) PublicKey() *rsa.PublicKey {
	//default behavior
	if ek.CatchPublicKey == nil {
		return ek.data.PK
	}
	return ek.CatchPublicKey()
}
func (ek *MockEndorsementKey) Certificate() *x509.Certificate {
	if ek.CatchCertificate == nil {
		return ek.data.C
	}
	return ek.CatchCertificate()
}

var GetFakeEndorsementKeyValid = func() tpm.EndorsementKey {
	fake := &MockEndorsementKey{}
	data := tpm.EndorsementKeyData{}
	raw := []byte("{\"certificate\":\"MIIFcTCCBFmgAwIBAgIEJLzerzANBgkqhkiG9w0BAQUFADB3MQswCQYDVQQGEwJERTEPMA0GA1UECBMGU2F4b255MSEwHwYDVQQKExhJbmZpbmVvbiBUZWNobm9sb2dpZXMgQUcxDDAKBgNVBAsTA0FJTTEmMCQGA1UEAxMdSUZYIFRQTSBFSyBJbnRlcm1lZGlhdGUgQ0EgMDUwHhcNMTgwMTI4MjEzODI2WhcNMjQxMTE3MjM1OTU5WjAAMIIBNzAiBgkqhkiG9w0BAQcwFaITMBEGCSqGSIb3DQEBCQQEVENQQQOCAQ8AMIIBCgKCAQEA3NXuBZ6JEJdnyDq6M4PfENLVrIGgMP+ANn2KOI+ivJ5BcMPGG74U7Nve3r4bpJzsJmnwoMRGlXt4scLccm3QCmH9obhR1gxCxeL5zhRmoJA5Oac342NaDRh5XJ24gaqDVZHntSX1ttsshgCgst62Cbmc9XxIyZJV5qPSJ0XP0mCOTRd9Dyhd9gol7EaBOHxQ3p/2THQvzI0eJvKT3GW5hLokBCSaOzkQ9iZHhFWgXqCshAJ3tO8H6BjDs/YprA2bWrlhKSAbg6ArFsWh2yntLTSnaT2auxz/wTb12D+0kIQikt52ItZbb9EpEmYFZWb9p7X+/E5207LZG8JbdxwO6wIDAQABo4ICZTCCAmEwVQYDVR0RAQH/BEswSaRHMEUxFjAUBgVngQUCAQwLaWQ6NDk0NjU4MDAxFzAVBgVngQUCAgwMU0xCOTYzNVRUMS4yMRIwEAYFZ4EFAgMMB2lkOjAzMTEwDAYDVR0TAQH/BAIwADCBvAYDVR0gAQH/BIGxMIGuMIGrBgtghkgBhvhFAQcvATCBmzA5BggrBgEFBQcCARYtaHR0cDovL3d3dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9yeS9pbmRleC5odG1sMF4GCCsGAQUFBwICMFIeUABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAgAE0AbwBkAHUAbABlACAARQBuAGQAbwByAHMAZQBtAGUAbgB0MIGkBgNVHSMEgZwwgZmAFLvPfMGEITFm2rW+U6hwFN3TSNjMoXukeTB3MQswCQYDVQQGEwJERTEPMA0GA1UECBMGU2F4b255MSEwHwYDVQQKExhJbmZpbmVvbiBUZWNobm9sb2dpZXMgQUcxDDAKBgNVBAsTA0FJTTEmMCQGA1UEAxMdSUZYIFRQTSBFSyBJbnRlcm1lZGlhdGUgQ0EgMDWCBAV1EnMwgZMGA1UdCQSBizCBiDA6BgNVBDQxMzALMAkGBSsOAwIaBQAwJDAiBgkqhkiG9w0BAQcwFaITMBEGCSqGSIb3DQEBCQQEVENQQTAWBgVngQUCEDENMAsMAzEuMgIBAgIBAjAyBgVngQUCEjEpMCcBAf+gAwoBAaEDCgEAogMKAQCjEDAOFgMzLjEKAQQKAQIBAf8BAf8wDQYJKoZIhvcNAQEFBQADggEBADEkZl8L/XgsuL94TF4OdV1XlxEPeTpqh05IWtDqPTKdLqmTTDEC/BAI4nRlnSgvJU7lsGzmCtK4Fwl+JRzIVKNQcdsXpIbQN5POQmcSgNXF0oamZ0ROh/M1VahfZh/l5q6eeeME/zF/fPQmPfXuMUoLzeCcPiX416XRfJYYuAHiJJDoepDiel4BMRL3TLW5EzWYT/xkKjlypUUB2UnpJm4NR/UWfp+FflBFVZk+739Jq4uXYKos1rE0D+HiTbIMl/HNVd2ohxD727g+7lb6vzH62OLwpJidt/W74Q4g44lzH0pEUy77DS8PLRgGoUfopW9gz70mY7CpwQy7e9vMctw=\"}")
	err := json.Unmarshal(raw, &data)
	if err != nil {
		log.Fatal(err)
	}
	fake.data = data
	return fake
}

var GetFakeEndorsementKeyInvalid = func() tpm.EndorsementKey {
	return &MockEndorsementKey{
		data: tpm.EndorsementKeyData{
			PK: &rsa.PublicKey{
				N: big.NewInt(0),
				E: 65537,
			},
			C: nil,
		},
	}
}
