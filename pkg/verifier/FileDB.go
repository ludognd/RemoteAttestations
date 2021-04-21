package verifier

import (
	"bufio"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"os"
	"strconv"
	"strings"
)

type FileDB struct {
	filepath string
}

func (f FileDB) GetPCRs() ([]tpm.PCR, error) {
	file, err := os.Open(f.filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	pcrs := []tpm.PCR{}
	id := 0
	for scanner.Scan() {
		line := scanner.Text()
		vals := strings.Split(strings.TrimSpace(line), " ")[1:]
		pcr := tpm.PCR{
			Id:    id,
			Value: []byte{},
		}
		for _, v := range vals {
			n, err := strconv.ParseInt(v, 16, 32)
			if err != nil {
				return nil, err
			}
			pcr.Value = append(pcr.Value, byte(n))
		}
		id += 1
		pcrs = append(pcrs, pcr)
	}
	return pcrs, err
}
