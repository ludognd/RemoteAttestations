package main

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/pkg/verifier"
	"github.com/xcaliburne/RemoteAttestations/pkg/verifier/RestServer"
	"gopkg.in/yaml.v3"
	"io/ioutil"
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
	configFile = flag.String("configFile", "configs/verifier.yaml", "Path to the configFile file")
	port       = flag.String("port", "8081", "Listening port")
	address    = flag.String("address", "127.0.0.1", "Listening port")
)

func parseConfig(configPath string) (*Config, error) {
	var conf Config
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Error reading YAML file: %s\n", err)
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
		log.Errorf("Error creating verifier: %v", err)
	}
	v := verifier.NewVerifier(&conf.Verifier)

	server := RestServer.RunServer(&conf.Rest, v)

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
				log.Info("stopping attesations")
				return
			default:
				v.StartAttestations()
			}
			time.Sleep(time.Duration(conf.Verifier.AttestationInterval) * time.Second)
		}
	}()

	<-c
	//Stop attestations
	close(quit)
	err = RestServer.StopServer(server)
	if err != nil {
		log.Error(err)
	}
	wg.Wait()
}
