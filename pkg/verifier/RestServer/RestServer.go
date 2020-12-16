package RestServer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/xcaliburne/RemoteAttestations/pkg/tpm"
	"github.com/xcaliburne/RemoteAttestations/pkg/verifier"
	"net/http"
	"time"
)

type Config struct {
	Address string
	Port    string
	stop    bool
}

var v verifier.Verifier

func handleRequests(router *mux.Router) {
	router.HandleFunc("/", helloWorld).Methods("GET")
	router.HandleFunc("/getNewEdgeInitParameters", getNewEdgeInitParameters).Methods("GET")
	router.HandleFunc("/registerNewEK", registerNewEK).Methods("POST")
	router.HandleFunc("/registerNewAK", registerNewAK).Methods("POST")
}

func RunServer(config *Config, verifier verifier.Verifier) *http.Server {
	v = verifier
	router := mux.NewRouter().StrictSlash(true)
	handleRequests(router)
	srv := &http.Server{
		Addr:         config.Address + ":" + config.Port,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router, // Pass our instance of gorilla/mux in.
	}
	log.Info(fmt.Sprintf("starting up REST API on %s:%s\n", config.Address, config.Port))
	go func() {
		defer log.Info("server goroutine terminated")
		if err := srv.ListenAndServe(); err != nil {
			log.Info(err)
		}
	}()
	return srv
}

func StopServer(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return server.Shutdown(ctx)
}

func helloWorld(w http.ResponseWriter, r *http.Request) {
	log.Info(r.URL)
	_, err := w.Write([]byte("Hello World!"))
	if err != nil {
		log.Error(err)
	}
}

func getNewEdgeInitParameters(w http.ResponseWriter, r *http.Request) {
	log.Info(r.URL)
	jsonResp, err := json.Marshal(v.InitParams())
	if err != nil {
		http.Error(w, "error marshaling json", 500)
	}
	fmt.Println(string(jsonResp))
	_, err = w.Write(jsonResp)
	if err != nil {
		log.Error(err)
	}
}

func registerNewEK(w http.ResponseWriter, r *http.Request) {
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
	err = v.RegisterNewEK(&p)
	if err != nil {
		log.Error("error registering EK: ", err)
		http.Error(w, "error registering EK", 500)
	}
	_, err = w.Write([]byte("success"))
	if err != nil {
		log.Error(err)
	}
}

func registerNewAK(w http.ResponseWriter, r *http.Request) {
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
	err = v.RegisterNewAK(&p)
	if err != nil {
		log.Error("error registering AK: ", err)
		http.Error(w, "error registering AK", 500)
	}
	_, err = w.Write([]byte("success\n"))
	if err != nil {
		log.Error(err)
	}
}
