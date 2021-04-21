package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	p "github.com/xcaliburne/RemoteAttestations/internal/prover"
	"github.com/xcaliburne/RemoteAttestations/internal/prover/RestServer"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type Config struct {
	Rest   RestServer.Config `yaml:"rest"`
	Prover p.Config          `yaml:"prover"`
}

var (
	configFile    = flag.String("config", "configs/prover.yaml", "Path to the config file")
	address       = flag.IPP("address", "a", net.IP{0, 0, 0, 0}, "Listening address")
	port          = flag.StringP("port", "p", "8080", "Listening port")
	name          = flag.StringP("name", "n", "prover", "Name of the prover")
	ak            = flag.String("ak", "ak.json", "Path to the AK file")
	ownerPassword = flag.String("owner_password", "tpmOwnerPassword", "tpm owner password")
	userPassword  = flag.String("user_password", "tpmUserPassword", "tpm user password")
	verifierUrl   = flag.String("verifier_url", "", "Verifier Listening URL")
)

func parseConfig(configPath string) (*Config, error) {
	//Set default values
	conf := Config{}
	addr, err := p.HttpUrlParser(*verifierUrl)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("%+v\n", conf)
	conf.Rest.Address = *address
	conf.Rest.Port = *port
	conf.Prover.Name = *name
	conf.Prover.AKFile = *ak
	conf.Prover.OwnerPassword = *ownerPassword
	conf.Prover.UserPassword = *userPassword
	conf.Prover.VerifierAddress = addr
	flag.Parse()
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Error reading YAML file: %s\n", err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, &conf)
	if err != nil {
		return nil, err
	}
	wasSet := func(name string) bool {
		wasSet := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == name {
				wasSet = true
			}
		})
		return wasSet
	}
	//Override config file with command line values
	if wasSet("address") {
		conf.Rest.Address = *address
	}
	if wasSet("port") {
		conf.Rest.Port = *port
	}
	if wasSet("name") {
		conf.Prover.Name = *name
	}
	if wasSet("ak") {
		conf.Prover.AKFile = *ak
	}
	if wasSet("owner_password") {
		conf.Prover.OwnerPassword = *ownerPassword
	}
	if wasSet("user_password") {
		conf.Prover.UserPassword = *userPassword
	}
	if wasSet("verifier_url") {
		addr, err = p.HttpUrlParser(*verifierUrl)
		if err != nil {
			log.Fatal(err)
		}
		conf.Prover.VerifierAddress = addr
	}
	//fmt.Printf("%+v\n", conf)
	return &conf, nil
}

func main() {
	conf, err := parseConfig(*configFile)
	if err != nil {
		log.Errorf("error creating verifier: %v\n", err)
	}
	fmt.Printf("%+v\n", conf)
	prover, err := p.NewProver(&conf.Prover)
	if err != nil {
		log.Fatal(err)
	}
	err = prover.Register(conf.Rest.Address.String(), conf.Rest.Port)
	if err != nil {
		log.Fatal(err)
	}
	server, err := RestServer.NewServer(&conf.Rest, prover)
	if err != nil {
		log.Fatal(err)
	}
	server.Run()
	//Signal that listens on OS signals
	signalChan := make(chan os.Signal, 1)
	//Listens to SIGINT only (ctrl+c)
	var t os.Signal
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGTERM, os.Kill)

	t = <-signalChan
	fmt.Println("received ", t.String())
	err = server.Stop()
	if err != nil {
		log.Error(err)
	}
}
