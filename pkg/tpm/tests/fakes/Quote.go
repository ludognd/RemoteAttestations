package fakes

import "github.com/xcaliburne/RemoteAttestations/pkg/tpm"

func GetFakeQuote() tpm.Quote {
	return &tpm.QuoteData{
		Raw: []byte("AQEAAFFVT1TEYnueIp5d+Zg60sE0UU4enka5N2Nc3z/Ng3rR3Aq4iYY3GYbEyPsK"),
		Parsed: struct {
			Version [4]byte
			Fixed   [4]byte
			Digest  [20]byte
			Nonce   [20]byte
		}{
			Version: [4]byte{1, 1, 0, 0},
			Fixed:   [4]byte{81, 85, 79, 84},
			Digest:  [20]byte{196, 98, 123, 158, 34, 158, 93, 249, 152, 58, 210, 193, 52, 81, 78, 30, 158, 70, 185, 55},
			Nonce:   [20]byte{99, 92, 223, 63, 205, 131, 122, 209, 220, 10, 184, 137, 134, 55, 25, 134, 196, 200, 251},
		},
		Signature: []byte("YcmMu4iwAfT0rKgMRDq6gJFVgYuiLsJi/3DIqXZsf2bjxEW/0DdZmh7s905z+hoNQm/eH/v3UfPQ9c2Bc83hD8ecTqL6ZlQIEQ18nnK7hVf3PsR/JWAATaToVPsHmOyIZhxxburw1zWg46rhOwVBY/dLOXjB9qap7l668Xb5/EkBUnNdUHIA6Ap3+vZhlmetPY2IR4RO1qYt5vsDKlw70mMetJ4skwQjP/J/80N0hvCUpjeW025RWFpLGfzTu2YPLdgXQhmMW+fPxTGajlBNUYxeeUqkW5UZ8uzJIik+L4kggjWfAiPXsmrL9kMFxvqCLDA/kXsMy/fHnk5jdsy4xQ=="),
	}
}
