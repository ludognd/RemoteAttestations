package verifier

import "github.com/xcaliburne/RemoteAttestations/pkg/tpm"

type DBConnector interface {
	GetPCRs() ([]tpm.PCR, error)
}
