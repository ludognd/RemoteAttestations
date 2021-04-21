package fakes

import (
	"crypto/rsa"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"math/big"
)

var GetFakeAttestationKeyValid = func() *tpm.AttestationKeyData {
	return &tpm.AttestationKeyData{
		PK: &rsa.PublicKey{
			N: big.NewInt(0),
			E: 65537,
		},
		B: []byte("AQEAAAASAAAAAAAAAAABAAEAAgAAAAwAAAgAAAAAAgAAAAAAAAAAAAABAIO4+v1DMz81k06OeXvoA6/ToR4qeS8nEFuh8efIiPYTwzy8imof2l+kPTw8LEp5RXf5/AR7P3T+z2nb6RPV63hYIdfG1ZxWMy4hyLb6XSDj2s+OT7CliECiUeqKIu2XBo1d+KlVefPTYRkKo+kXxupuu12lufeZyBJMHuz9xyIB8AJ3LaMiS1D2Fqd3rrbpXudWSWlk+dgSAny0kJUzTJzOVbpyn77TiPDlxaCMSCwm6si6uBgi8rSlME7kfA9YE5W/e4CewOiMnepOIuBvK4y5gSOTKQU+ZYF/UAdUqG6u9g8N6FFtI1BXI5Db0XJbZHtbyrPJd143BQeWpbT7absAAAEAG4xowLP1ovBsv4UaSWawcn4JhwKkyAgviQHrY0kt+pc3clhZDCMewr/eRJGob/d7YwWdvVMSwmdV9T6yjJYiFpnJbKDfqy41Kj/32yR6l3YNiciKPOolL77AuMEnybS2mcO5nctcpkIo+IxSIbB0EmNuLY9SSOeeJr1OkY8EV3pdLh5wixiBMVHBmiQ6srQyO+oZvuYIapSqKeCFz8LWo+CBR+2gBaiX/Ed/zl9csbVC1HvmZVcra4inQNdVhOELnRoaz0pCODY/WhOKDu45VDqBN5LxxJ5QGjI9PwD+oiDHprN6RJVUIkJdLzChJHWFUh32mb956Ivinw5BkYQUXw=="),
	}
}

var GetFakeAttestationKeyInvalid = func() *tpm.AttestationKeyData {
	return &tpm.AttestationKeyData{
		PK: &rsa.PublicKey{
			N: big.NewInt(0),
			E: 1,
		},
		B: []byte(""),
	}
}
