package tpm

import (
	"fmt"
	"github.com/google/go-tpm/tpmutil"
	"sort"
)

var All_pcrs = [...]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}

type PCR struct {
	Id    int
	Value []byte
}

// Creates a PCR composite as stated in tspiTPM-Main-Part-2-tspiTPM-Structures_v1.2_rev116_01032011.pdf section 5.4.1
func pcrsToComposite(pcrs []PCR) ([]byte, error) {
	sort.Slice(pcrs, func(i, j int) bool { return pcrs[i].Id < pcrs[j].Id })
	var bitmap [3]byte   //24 PCRs bitmap
	var valBuffer []byte //Buffer for serialized values
	for _, pcr := range pcrs {
		if pcr.Id < 0 || pcr.Id >= 24 {
			return nil, fmt.Errorf("invalid PCR index: %d", pcr.Id)
		}
		bitmapId := pcr.Id / cap(bitmap)
		shift := pcr.Id % 8
		bitmap[bitmapId] |= 1 << shift
		valBuffer = append(valBuffer, pcr.Value...)
	}

	return tpmutil.Pack(3, bitmap, valBuffer)
}
