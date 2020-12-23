package RestServer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/internal/prover"
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
	p      prover.Prover
}

func (rest *RestServer) handleRequests(router *mux.Router) {
	router.HandleFunc("/", rest.test).Methods("POST", "GET")
	router.HandleFunc("/attest", rest.attest).Methods("POST")
}

func NewServer(config *Config, prover prover.Prover) (*RestServer, error) {
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
		p:      prover,
	}
	restServer.handleRequests(router)
	return restServer, nil
}

func (rest *RestServer) Run() {
	log.Info(fmt.Sprintf("starting up REST API on %s\n", rest.server.Addr))
	go func() {
		defer log.Info("server goroutine terminated")
		if err := rest.server.ListenAndServe(); err != nil {
			log.Info(err)
		}
	}()
}

func (rest *RestServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	return rest.server.Shutdown(ctx)
}

func (rest *RestServer) test(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Hello World!\n"))
	if err != nil {
		log.Error(err)
	}
}

func (rest *RestServer) attest(w http.ResponseWriter, r *http.Request) {
	log.Info(r.URL)
	decoder := json.NewDecoder(r.Body)
	var queryBody = struct {
		Nonce []byte
	}{}
	err := decoder.Decode(&queryBody)
	if err != nil {
		log.Error("error decoding nonce: ", err)
		http.Error(w, "error decoding nonce", http.StatusBadRequest)
		return
	}
	if len(queryBody.Nonce) == 0 {
		log.Error("empty nonce")
		http.Error(w, "empty nonce", http.StatusBadRequest)
		return
	}
	attestation, err := rest.p.Attest(queryBody.Nonce[:])
	if err != nil {
		log.Error("error computing attestation: ", err)
		http.Error(w, "error computing attestation", http.StatusInternalServerError)
		return
	}
	respBody, err := json.Marshal(attestation)
	if err != nil {
		log.Error("error marshaling response: ", err)
		http.Error(w, "error marshaling response", http.StatusInternalServerError)
		return
	}
	_, err = w.Write(respBody)
	if err != nil {
		log.Error("error writing response: ", err)
		http.Error(w, "error writing response", http.StatusInternalServerError)
		return
	}
}
