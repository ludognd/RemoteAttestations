package RestServer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"github.com/xcaliburne/RemoteAttestations/pkg/verifier"
	"net"
	"net/http"
	"time"
)

type Config struct {
	Address net.IP `yaml:"address"`
	Port    string `yaml:"port"`
}

type RestServer struct {
	config *Config
	server *http.Server
	v      verifier.Verifier
}

func (s *RestServer) handleRequests(router *mux.Router) {
	router.HandleFunc("/", s.helloWorld).Methods("GET")
	router.HandleFunc("/getNewEdgeInitParameters", s.getNewEdgeInitParameters).Methods("GET")
	router.HandleFunc("/registerNewEK", s.registerNewEK).Methods("POST")
	router.HandleFunc("/registerNewAK", s.registerNewAK).Methods("POST")
}

func NewServer(config *Config, verifier verifier.Verifier) (*RestServer, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(config.Address.String(), config.Port))
	if err != nil {
		return nil, err
	}
	router := mux.NewRouter().StrictSlash(true)
	httpServer := &http.Server{
		Addr:         tcpAddr.String(),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router, // Pass our instance of gorilla/mux in.
	}
	restServer := &RestServer{
		config: config,
		server: httpServer,
		v:      verifier,
	}
	restServer.handleRequests(router)
	return restServer, nil
}

func (s *RestServer) Run() {
	log.Info(fmt.Sprintf("starting up REST API on %s\n", s.server.Addr))
	go func() {
		defer log.Info("server goroutine terminated")
		if err := s.server.ListenAndServe(); err != nil {
			log.Info(err)
		}
	}()
}

func (s *RestServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *RestServer) helloWorld(w http.ResponseWriter, r *http.Request) {
	log.Info(r.URL)
	_, err := w.Write([]byte("Hello World!\n"))
	if err != nil {
		log.Error(err)
	}
}

func (s *RestServer) getNewEdgeInitParameters(w http.ResponseWriter, r *http.Request) {
	log.Info(r.URL)
	jsonResp, err := json.Marshal(s.v.InitParams())
	if err != nil {
		http.Error(w, "error marshaling json", 500)
	}
	fmt.Println(string(jsonResp))
	_, err = w.Write(jsonResp)
	if err != nil {
		log.Error(err)
	}
}

func (s *RestServer) registerNewEK(w http.ResponseWriter, r *http.Request) {
	log.Info(r.URL)
	decoder := json.NewDecoder(r.Body)
	var queryBody = struct {
		Name     string
		Endpoint string
		Port     string
		EK       tpm.EndorsementKeyData
	}{}
	err := decoder.Decode(&queryBody)
	if err != nil {
		log.Error("error decoding EK: ", err)
		http.Error(w, "error decoding EK", 500)
	}
	p := verifier.Prover{EK: &queryBody.EK, Name: queryBody.Name, Endpoint: queryBody.Endpoint, Port: queryBody.Port}
	err = s.v.RegisterNewEK(&p)
	if err != nil {
		if err.Error() != "error storing new EK: endorsement key already set\n"{
			log.Error("error registering EK: ", err)
			http.Error(w, "error registering EK", 500)
		}else {
			err = nil
		}
	}
	_, err = w.Write([]byte("success"))
	if err != nil {
		log.Error(err)
	}
}

func (s *RestServer) registerNewAK(w http.ResponseWriter, r *http.Request) {
	log.Info(r.URL)
	decoder := json.NewDecoder(r.Body)
	var queryBody = struct {
		EK *tpm.EndorsementKeyData
		AK *tpm.AttestationKeyData
	}{}
	err := decoder.Decode(&queryBody)
	if err != nil {
		log.Error("error decoding AK: ", err)
		http.Error(w, "error decoding AK", 500)
	}
	p := verifier.Prover{EK: queryBody.EK, AK: queryBody.AK}
	err = s.v.RegisterNewAK(&p)
	if err != nil {
		if err.Error() != "error storing new AK: attestation key already set\n"{
			log.Error("error registering AK: ", err)
			http.Error(w, "error registering AK", 500)
		}else {
			err = nil
		}
	}
	_, err = w.Write([]byte("success\n"))
	if err != nil {
		log.Error(err)
	}
}
