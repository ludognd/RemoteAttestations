package RestServer

import (
	"encoding/json"
	//"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/pkg/prover"
	"net/http"
)

type Config struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

var p *prover.Prover

func handleRequests(router *mux.Router) {
	router.HandleFunc("/", test).Methods("POST", "GET")
	router.HandleFunc("/attest", attest).Methods("POST")
}

func RunServer(config *Config, prover *prover.Prover) error {
	p = prover
	router := mux.NewRouter().StrictSlash(true)
	handleRequests(router)
	err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		tpl, _ := route.GetPathTemplate()
		met, _ := route.GetMethods()
		fmt.Println(tpl, met)
		return nil
	})
	if err != nil {
		log.Error(err)
	}
	fmt.Printf("Starting up on %s:%s\n", config.Address, config.Port)
	return http.ListenAndServe(config.Address+":"+config.Port, router)
}

func test(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Hello World!\n"))
	if err != nil {
		log.Error(err)
	}
}

func attest(w http.ResponseWriter, r *http.Request) {
	log.Info(r.URL)
	decoder := json.NewDecoder(r.Body)
	var queryBody = struct {
		Nonce []byte
	}{}
	err := decoder.Decode(&queryBody)
	if err != nil {
		log.Error("error decoding nonce: ", err)
		http.Error(w, "error decoding nonce", 500)
		return
	}
	attestation, err := p.Attest(queryBody.Nonce[:])
	if err != nil {
		log.Error("error computing attestation: ", err)
		http.Error(w, "error computing attestation", 500)
		return
	}
	respBody, err := json.Marshal(attestation)
	if err != nil {
		log.Error("error marshaling response: ", err)
		http.Error(w, "error marshaling response", 500)
		return
	}
	_, err = w.Write(respBody)
	if err != nil {
		log.Error("error writing response: ", err)
		http.Error(w, "error writing response", 500)
		return
	}
}
