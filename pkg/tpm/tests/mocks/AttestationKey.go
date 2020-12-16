package mocks

import (
	"crypto/rsa"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"math/big"
)

type MockAttesationKey struct {
	CatchSave      func(filePath string) error
	catchPublicKey func() *rsa.PublicKey
	CatchBlob      func() []byte
	data           *tpm.AttestationKeyData
}

var _ tpm.AttestationKey = (*MockAttesationKey)(nil) // Verify that *MockAttesationKey implements AttestationKey.

func (ak *MockAttesationKey) Save(filePath string) error {
	//default behavior
	if ak.CatchSave == nil {
		return nil
	}
	return ak.CatchSave(filePath)
}

func (ak *MockAttesationKey) PublicKey() *rsa.PublicKey {
	//default behavior
	if ak.catchPublicKey == nil {
		return ak.data.PK
	}
	return ak.catchPublicKey()
}

func (ak *MockAttesationKey) Blob() []byte {
	//default behavior
	if ak.CatchBlob == nil {
		return ak.data.B
	}
	return ak.CatchBlob()
}

var GetFakeAttestationKeyValid = func() tpm.AttestationKey {
	fake := &MockAttesationKey{
		CatchSave:      nil,
		catchPublicKey: nil,
		CatchBlob:      nil,
		data: &tpm.AttestationKeyData{
			PK: &rsa.PublicKey{
				N: big.NewInt(0),
				E: 65537,
			},
			B: []byte("AQEAAAASAAAAAAAAAAABAAEAAgAAAAwAAAgAAAAAAgAAAAAAAAAAAAABAIO4+v1DMz81k06OeXvoA6/ToR4qeS8nEFuh8efIiPYTwzy8imof2l+kPTw8LEp5RXf5/AR7P3T+z2nb6RPV63hYIdfG1ZxWMy4hyLb6XSDj2s+OT7CliECiUeqKIu2XBo1d+KlVefPTYRkKo+kXxupuu12lufeZyBJMHuz9xyIB8AJ3LaMiS1D2Fqd3rrbpXudWSWlk+dgSAny0kJUzTJzOVbpyn77TiPDlxaCMSCwm6si6uBgi8rSlME7kfA9YE5W/e4CewOiMnepOIuBvK4y5gSOTKQU+ZYF/UAdUqG6u9g8N6FFtI1BXI5Db0XJbZHtbyrPJd143BQeWpbT7absAAAEAG4xowLP1ovBsv4UaSWawcn4JhwKkyAgviQHrY0kt+pc3clhZDCMewr/eRJGob/d7YwWdvVMSwmdV9T6yjJYiFpnJbKDfqy41Kj/32yR6l3YNiciKPOolL77AuMEnybS2mcO5nctcpkIo+IxSIbB0EmNuLY9SSOeeJr1OkY8EV3pdLh5wixiBMVHBmiQ6srQyO+oZvuYIapSqKeCFz8LWo+CBR+2gBaiX/Ed/zl9csbVC1HvmZVcra4inQNdVhOELnRoaz0pCODY/WhOKDu45VDqBN5LxxJ5QGjI9PwD+oiDHprN6RJVUIkJdLzChJHWFUh32mb956Ivinw5BkYQUXw=="),
		},
	}
	fake.data.PK.N.SetBytes([]byte("16628435198810462005307945923322229954774007194741580914416524513436428322284870979217262806119394107916060677477870734288025278693334906657691291483506942330187203484238111712512618821507992452564648311401436712108595608522096515941746407170767093190740116393224653578589892820629149970291121051325762071467969237932010001329680253745097188309151687808799541185837067749266406670767277591251768539108191490310336295870776210587459137426385680623792787160357831628614368274649111704412629795749240494146666354699315365998453108800558073349774413834110730183132375337028074268780463866999756971589399098083378116389307"))
	return fake
}

var GetFakeAttestationKeyInvalid = func() tpm.AttestationKey {
	return &MockAttesationKey{
		CatchSave:      nil,
		catchPublicKey: nil,
		CatchBlob:      nil,
		data: &tpm.AttestationKeyData{
			PK: &rsa.PublicKey{
				N: big.NewInt(0),
				E: 1,
			},
			B: []byte(""),
		},
	}
}
