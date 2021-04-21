package main

import (
	"fmt"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"os"
	"strconv"
)

func main() {
	tpm, err := tpm.Open()
	if err != nil {
		fmt.Println(err)
	}

	pcrId, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println(err)
	}
	hash := os.Args[2]
	tpm.ExtendPCR(pcrId, []byte(hash), 0, "")
	pcrs := tpm.ListPCRs()
	fmt.Printf("Extending PCR %v with hash: %v\nNew PCR value: %v\n", pcrId, hash, pcrs[pcrId])
	//pcrs := tpm.ListPCRs()
	//for i, pcr := range pcrs {
	//	fmt.Printf("pcr %d: %08b\n", i, pcr.Value)
	//}
}
