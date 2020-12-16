package verifier

import "github.com/xcaliburne/RemoteAttestations/pkg/tpm"

type Prover struct {
	Name     string
	Endpoint string
	Port     string
	EK       tpm.EndorsementKey
	AK       tpm.AttestationKey
}
