package verifier

type InitializationParams struct {
	OwnerPassword string `yaml:"owner_password"`
	UserPassword  string `yaml:"user_password"`
}

type Config struct {
	Init                InitializationParams `yaml:"init"`
	AttestationInterval int                  `yaml:"attestation_interval"`
}
