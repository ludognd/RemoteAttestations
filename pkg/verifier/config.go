package verifier

import "time"

type InitializationParams struct {
	OwnerPassword string `yaml:"owner_password"`
	UserPassword  string `yaml:"user_password"`
}

type Config struct {
	Init                InitializationParams `yaml:"init"`
	AttestationInterval time.Duration        `yaml:"attestation_interval"`
}
