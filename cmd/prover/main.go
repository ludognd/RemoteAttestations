package main

import (
	"flag"
	log "github.com/sirupsen/logrus"
	p "github.com/xcaliburne/RemoteAttestations/pkg/prover"
	"github.com/xcaliburne/RemoteAttestations/pkg/prover/RestServer"
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

type Config struct {
	Rest   *RestServer.Config `yaml:"rest"`
	Prover *p.Config          `yaml:"prover"`
}

var configFile = flag.String("config", "conf/prover.yaml", "Path to the config file")

func parseConfig(configPath string) (*Config, error) {
	var conf Config
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}

func main() {
	flag.Parse()
	conf, err := parseConfig(*configFile)
	if err != nil {
		log.Errorf("error creating verifier: %v\n", err)
	}
	prover, err := p.NewProver(conf.Prover)
	if err != nil {
		log.Error(err)
	}
	err = prover.Register(conf.Rest.Address, conf.Rest.Port)
	if err != nil {
		log.Error(err)
	}
	log.Error(RestServer.RunServer(conf.Rest, prover))
}
