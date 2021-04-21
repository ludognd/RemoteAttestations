package tpm

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/go-tspi/tspi"
	"github.com/google/go-tspi/tspiconst"
	"io/ioutil"
	"sort"
)

var WellKnownSecret [20]byte

type TPM interface {
	Close() error
	TakeOwnership(ownerPassword, userPassword string) error
	IsOwned() (bool, error)
	ProveOwnership(ownerPassword string) error
	ProveUsership(userPassword string) error
	GetEK() (EndorsementKey, error)
	CreateAK() (AttestationKey, error)
	Quote(ak AttestationKey, nonce []byte, pcrIds []int) (Quote, error)
	ListPCRs() []PCR
	ExtendPCR(pcrId int, data []byte, eventId int, event string) error
}

type tspiTPM struct {
	contextHandle *tspi.Context
	tpmHandle     *tspi.TPM
}

var _ TPM = (*tspiTPM)(nil) // Verify that *tspiTPM implements TPM.

type OwnerToken *tspi.Policy
type UserToken *tspi.Key

func Open() (TPM, error) {
	return open()
}

func open() (TPM, error) {
	ctxt, err := tspi.NewContext()
	if err != nil {
		return nil, fmt.Errorf("error connecting: %v", err)
	}
	// Connect to the tspiTPM daemon
	err = ctxt.Connect()
	if err != nil {
		return nil, fmt.Errorf("Error connecting to daemon: %v", err)
	}
	// Obtain a handle to the tspiTPM itself
	return &tspiTPM{contextHandle: ctxt, tpmHandle: ctxt.GetTPM()}, nil
}

func (tpm *tspiTPM) Close() error {
	return tpm.contextHandle.Close()
}

// CAUTION, STORE PASSWORDS
func (tpm *tspiTPM) TakeOwnership(ownerPassword, userPassword string) error {
	srkPasswordDigest := sha1.Sum([]byte(userPassword))
	ownerPasswordDigest := sha1.Sum([]byte(ownerPassword))
	tpmPolicy, err := tpm.tpmHandle.GetPolicy(tspiconst.TSS_POLICY_USAGE)
	if err != nil {
		return fmt.Errorf("unable to obtain tspiTPM policy: %v", err)
	}
	err = tpmPolicy.SetSecret(tspiconst.TSS_SECRET_MODE_SHA1, ownerPasswordDigest[:])
	if err != nil {
		return fmt.Errorf("unable to set tspiTPM policy: %v", err)
	}

	srk, err := tpm.contextHandle.CreateKey(tspiconst.TSS_KEY_TSP_SRK | tspiconst.TSS_KEY_AUTHORIZATION)
	if err != nil {
		return fmt.Errorf("unable to create SRK: %v", err)
	}
	keyPolicy, err := srk.GetPolicy(tspiconst.TSS_POLICY_USAGE)
	if err != nil {
		return fmt.Errorf("unable to obtain SRK policy: %v", err)
	}
	err = keyPolicy.SetSecret(tspiconst.TSS_SECRET_MODE_SHA1, srkPasswordDigest[:])
	if err != nil {
		return fmt.Errorf("unable to set SRK policy: %v", err)
	}

	err = tpm.tpmHandle.TakeOwnership(srk)
	if err != nil {
		return fmt.Errorf("unable to take ownership: %v", err)
	}
	return nil
}

func (tpm *tspiTPM) IsOwned() (bool, error) {
	val, err := ioutil.ReadFile("/sys/class/tpm/tpm0/device/owned")
	if err != nil {
		return false, fmt.Errorf("unable to read tpm owned file: %v", err)
	}
	return !bytes.Equal(val, []byte("0\n")), nil
}

func (tpm *tspiTPM) ProveOwnership(ownerPassword string) error {
	ownerPasswordDigest := sha1.Sum([]byte(ownerPassword))
	tpmPolicy, err := tpm.tpmHandle.GetPolicy(tspiconst.TSS_POLICY_USAGE)
	if err != nil {
		return fmt.Errorf("GetPolicy failed: %v", err)
	}
	err = tpm.tpmHandle.AssignPolicy(tpmPolicy)
	if err != nil {
		return fmt.Errorf("AssignPolicy failed: %v", err)
	}
	err = tpmPolicy.SetSecret(tspiconst.TSS_SECRET_MODE_SHA1, ownerPasswordDigest[:])
	if err != nil {
		return fmt.Errorf("SetSecret failed: %v", err)
	}
	return nil
}

func (tpm *tspiTPM) ProveUsership(userPassword string) error {
	userPasswordDigest := sha1.Sum([]byte(userPassword))
	srk, err := tpm.contextHandle.LoadKeyByUUID(tspiconst.TSS_PS_TYPE_SYSTEM, tspi.TSS_UUID_SRK)
	if err != nil {
		return fmt.Errorf("LoadKeyByUUID failed: %v", err)
	}
	srkPolicy, err := srk.GetPolicy(tspiconst.TSS_POLICY_USAGE)
	if err != nil {
		return fmt.Errorf("GetPolicy failed: %v", err)
	}
	err = srkPolicy.SetSecret(tspiconst.TSS_SECRET_MODE_SHA1, userPasswordDigest[:])
	if err != nil {
		return fmt.Errorf("error setting srk secret: %v", err)
	}
	return nil
}

func (tpm *tspiTPM) getOwnerToken() (OwnerToken, error) {
	tpmPolicy, err := tpm.tpmHandle.GetPolicy(tspiconst.TSS_POLICY_USAGE)
	if err != nil {
		return nil, fmt.Errorf("GetPolicy failed: %v", err)
	}
	return tpmPolicy, nil
}

func (tpm *tspiTPM) getUserToken() (UserToken, error) {
	srk, err := tpm.contextHandle.LoadKeyByUUID(tspiconst.TSS_PS_TYPE_SYSTEM, tspi.TSS_UUID_SRK)
	if err != nil {
		return nil, fmt.Errorf("LoadKeyByUUID failed: %v", err)
	}
	return srk, nil
}

func (tpm *tspiTPM) GetEK() (EndorsementKey, error) {
	rawCert, err := tpm.getEKCert()
	if err != nil {
		return nil, fmt.Errorf("error getting EK: %v", err)
	}
	cert, err := parseEKCertificate(rawCert)
	if err != nil {
		return nil, fmt.Errorf("error parsing cert: %v", err)
	}
	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}
	return &EndorsementKeyData{PK: rsaPubKey, C: cert}, nil
}

// source: https://github.com/google/go-tspi/blob/master/attestation/attestation.go
func (tpm *tspiTPM) getEKCert() ([]byte, error) {
	ownerToken, err := tpm.getOwnerToken()
	if err != nil {
		return nil, err
	}
	nv, err := tpm.contextHandle.CreateNV()
	if err != nil {
		return nil, err
	}
	err = nv.SetIndex(0x1000f000)
	if err != nil {

	}
	err = nv.AssignPolicy(ownerToken)
	if err != nil {

	}
	data, err := nv.ReadValue(0, 5)
	if err != nil {
		fmt.Println("error: ", err)
		return nil, err
	}

	tag := (uint)(data[0])<<8 | (uint)(data[1])
	if tag != 0x1001 {
		return nil, fmt.Errorf("invalid tag: %x", tag)
	}
	if data[2] != 0 {
		return nil, fmt.Errorf("invalid C")
	}

	ekbuflen := uint(data[3])<<8 | (uint)(data[4])
	offset := (uint)(5)

	data, err = nv.ReadValue(offset, 2)

	tag = (uint)(data[0])<<8 | (uint)(data[1])
	if tag == 0x1002 {
		offset += 2
		ekbuflen -= 2
	} else if data[0] != 0x30 {
		return nil, fmt.Errorf("invalid header: %x", tag)
	}

	ekoffset := (uint)(0)
	var ekbuf []byte
	for ekoffset < ekbuflen {
		length := ekbuflen - ekoffset
		if length > 128 {
			length = 128
		}
		data, err = nv.ReadValue(offset, length)
		if err != nil {
			return nil, err
		}

		ekbuf = append(ekbuf, data...)
		offset += length
		ekoffset += length
	}
	return ekbuf, err
}

func (tpm *tspiTPM) CreateAK() (AttestationKey, error) {
	//We need to sign the new AIK with private CA key. We don't need CA so we are going to forge a well known one
	userToken, err := tpm.getUserToken()
	if err != nil {
		return nil, err
	}
	n := bytes.Repeat([]byte{0xff}, 256) //2048bit long key
	pcaKey, err := tpm.contextHandle.CreateKey(tspiconst.TSS_KEY_TYPE_LEGACY | tspiconst.TSS_KEY_SIZE_2048)
	if err != nil {
		return nil, err
	}
	err = pcaKey.SetModulus(n)
	if err != nil {
		return nil, err
	}

	aik, err := tpm.contextHandle.CreateKey(tspiconst.TSS_KEY_TYPE_IDENTITY | tspiconst.TSS_KEY_SIZE_2048)
	if err != nil {
		return nil, err
	}

	_, err = tpm.tpmHandle.CollateIdentityRequest(userToken, pcaKey, aik)
	if err != nil {
		return nil, err
	}

	pubKey, err := aik.GetPublicKey()
	if err != nil {
		return nil, err
	}
	blob, err := aik.GetKeyBlob()
	if err != nil {
		return nil, err
	}

	_, err = aik.GetModulus()
	if err != nil {
		return nil, err
	}
	return &AttestationKeyData{PK: pubKey, B: blob}, nil
}

func (tpm *tspiTPM) Quote(ak AttestationKey, nonce []byte, pcrIds []int) (Quote, error) {
	//start := time.Now()
	q := QuoteData{}
	userToken, err := tpm.getUserToken()
	if err != nil {
		return nil, err
	}
	aik, err := tpm.contextHandle.LoadKeyByBlob(userToken, ak.Blob())
	if err != nil {
		return nil, fmt.Errorf("LoadKeyByBlob failed: %v", err)
	}

	pcrs, err := tpm.contextHandle.CreatePCRs(tspiconst.TSS_PCRS_STRUCT_DEFAULT)
	if err != nil {
		return nil, fmt.Errorf("failed to get a reference to PCRs: %v", err)
	}

	sort.Ints(pcrIds)
	if err = pcrs.SetPCRs(pcrIds); err != nil {
		return nil, fmt.Errorf("failed to set the PCR bitmap %v", err)
	}
	q.Raw, q.Signature, err = tpm.tpmHandle.GetQuote(aik, pcrs, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to ParsedQuote %v", err)
	}
	parsed := ParsedQuote{}
	if _, err := tpmutil.Unpack(q.Raw, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse ParsedQuote: %v", err)
	}
	q.Parsed = parsed
	//duration := time.Now().Sub(start)
	//fmt.Printf("Quote time: %v\n", duration)
	return &q, nil
}

func (tpm *tspiTPM) ListPCRs() []PCR {
	pcrValues, err := tpm.tpmHandle.GetPCRValues()
	if err != nil {
		fmt.Println("Error fetching PCR values")
	}
	pcrs := make([]PCR, len(pcrValues))
	for i, val := range pcrValues {
		pcrs[i] = PCR{Id: i, Value: val}
	}
	return pcrs
}

func (tpm *tspiTPM) ExtendPCR(pcrId int, data []byte, eventId int, event string) error {
	eventBytes := []byte(event)
	if event == "" {
		eventBytes = nil
	}
	tpm.tpmHandle.ExtendPCR(pcrId, data, eventId, eventBytes)
	return nil
}
