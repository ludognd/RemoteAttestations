package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier"
	"github.com/xcaliburne/RemoteAttestations/internal/verifier/RestServer"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

type Config struct {
	Rest     RestServer.Config `yaml:"rest"`
	Verifier verifier.Config   `yaml:"verifier"`
}

var (
	configFile    = flag.StringP("config", "c", "configs/verifier.yaml", "Path to the configFile file")
	address       = flag.IPP("address", "a", net.IP{0, 0, 0, 0}, "Listening address")
	port          = flag.StringP("port", "p", "8080", "Listening port")
	ownerPassword = flag.String("owner_password", "tpmOwnerPassword", "tpm owner password")
	userPassword  = flag.String("user_password", "tpmUserPassword", "tpm user password")
	interval      = flag.DurationP("attestation_interval", "i", time.Duration(15)*time.Minute, "Interval between two attestations")
)

func parseConfig() (*Config, error) {
	//Set default values
	conf := Config{}
	conf.Rest.Address = *address
	conf.Rest.Port = *port
	conf.Verifier.Init.OwnerPassword = *ownerPassword
	conf.Verifier.Init.UserPassword = *userPassword
	conf.Verifier.AttestationInterval = *interval
	flag.Parse()
	yamlFile, err := ioutil.ReadFile(*configFile)
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
	if wasSet("port") {
		conf.Rest.Port = *port
	}
	if wasSet("address") {
		conf.Rest.Address = *address
	}
	if wasSet("owner_password") {
		conf.Verifier.Init.OwnerPassword = *ownerPassword
	}
	if wasSet("user_password") {
		conf.Verifier.Init.OwnerPassword = *userPassword
	}
	if wasSet("attestation_interval") {
		conf.Verifier.AttestationInterval = *interval
	}
	fmt.Printf("%+v\n", conf)
	return &conf, nil
}

func main() {
	conf, err := parseConfig()
	if err != nil {
		log.Fatalf("Error creating verifier: %v", err)
	}
	v := verifier.NewVerifier(&conf.Verifier)
	server, err := RestServer.NewServer(&conf.Rest, v)
	if err != nil {
		log.Fatalf("Error creating server: %v", err)
	}
	server.Run()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	var wg sync.WaitGroup

	quit := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-quit:
				log.Info("stopping attestations")
				return
			default:
				v.StartAttestations()
			}
			time.Sleep(conf.Verifier.AttestationInterval)
		}
	}()

	<-c
	//Stop attestations
	close(quit)
	err = server.Stop()
	if err != nil {
		log.Error(err)
	}
	wg.Wait()
}
