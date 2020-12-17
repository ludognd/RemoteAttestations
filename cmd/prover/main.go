package main

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	p "github.com/xcaliburne/RemoteAttestations/pkg/prover"
	"github.com/xcaliburne/RemoteAttestations/pkg/prover/RestServer"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
)

type Config struct {
	Rest   *RestServer.Config `yaml:"rest"`
	Prover *p.Config          `yaml:"prover"`
}

var configFile = flag.String("config", "configs/prover.yaml", "Path to the config file")

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
	server := RestServer.RunServer(conf.Rest, prover)

	//Signal that listens on OS signals
	signalChan := make(chan os.Signal, 1)
	//Listens to SIGINT only (ctrl+c)
	var t os.Signal
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGTERM, os.Kill)

	t = <-signalChan
	fmt.Println("received ", t.String())
	err = RestServer.StopServer(server)
	if err != nil {
		log.Error(err)
	}
}
