package fakes

import (
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"github.com/xcaliburne/RemoteAttestations/pkg/verifier"
)

func GetFakeProver(getEK func() tpm.EndorsementKey, getAK func() tpm.AttestationKey) verifier.Prover {
	return verifier.Prover{
		Name:     "test",
		Endpoint: "127.0.0.1",
		Port:     "8080",
		EK:       getEK(),
		AK:       getAK(),
	}
}
