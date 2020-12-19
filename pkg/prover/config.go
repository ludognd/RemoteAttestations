package prover

import (
	"net/url"
	"strings"
)

type Config struct {
	Name            string   `yaml:"name"`
	AKFile          string   `yaml:"attestation_key"`
	OwnerPassword   string   `yaml:"owner_password"`
	UserPassword    string   `yaml:"user_password"`
	VerifierAddress *url.URL `yaml:"verifier_url"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s struct {
		Name            string `yaml:"name"`
		AKFile          string `yaml:"attestation_key"`
		OwnerPassword   string `yaml:"owner_password"`
		UserPassword    string `yaml:"user_password"`
		VerifierAddress string `yaml:"verifier_url"`
	}
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	//TODO: Fix c.VerifierAddress parsing
	c.VerifierAddress, err = HttpUrlParser(s.VerifierAddress)
	if err != nil {
		return err
	}
	return nil
}

func HttpUrlParser(s string) (*url.URL, error) {
	if !strings.HasPrefix(s, "http") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return u, nil
}
