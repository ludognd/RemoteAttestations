package httpClient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"
)

type Debug struct {
	DNS struct {
		Start   string       `json:"start"`
		End     string       `json:"end"`
		Host    string       `json:"host"`
		Address []net.IPAddr `json:"address"`
		Error   error        `json:"error"`
	} `json:"dns"`
	Dial struct {
		Start string `json:"start"`
		End   string `json:"end"`
	} `json:"dial"`
	Connection struct {
		Time string `json:"time"`
	} `json:"connection"`
	WroteAllRequestHeaders struct {
		Time string `json:"time"`
	} `json:"wrote_all_request_header"`
	WroteAllRequest struct {
		Time string `json:"time"`
	} `json:"wrote_all_request"`
	FirstReceivedResponseByte struct {
		Time string `json:"time"`
	} `json:"first_received_response_byte"`
}

type HttpClient interface {
	Post(url string, contentType string, body []byte) (*http.Response, error)
	Get(url string) (*http.Response, error)
}

type DataHttpClient struct {
	client *http.Client
}

var _ HttpClient = (*DataHttpClient)(nil)
var Client HttpClient

func init() {
	Client = &DataHttpClient{
		client: &http.Client{
			Timeout: time.Second * 10,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				DisableKeepAlives:     true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func trace() (*httptrace.ClientTrace, *Debug) {
	d := &Debug{}

	t := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			t := time.Now().UTC().String()
			log.Println(t, "dns start")
			d.DNS.Start = t
			d.DNS.Host = info.Host
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			t := time.Now().UTC().String()
			log.Println(t, "dns end")
			d.DNS.End = t
			d.DNS.Address = info.Addrs
			d.DNS.Error = info.Err
		},
		ConnectStart: func(network, addr string) {
			t := time.Now().UTC().String()
			log.Println(t, "dial start")
			d.Dial.Start = t
		},
		ConnectDone: func(network, addr string, err error) {
			t := time.Now().UTC().String()
			log.Println(t, "dial end")
			d.Dial.End = t
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			t := time.Now().UTC().String()
			log.Println(t, "conn time")
			d.Connection.Time = t
		},
		WroteHeaders: func() {
			t := time.Now().UTC().String()
			log.Println(t, "wrote all request headers")
			d.WroteAllRequestHeaders.Time = t
		},
		WroteRequest: func(wr httptrace.WroteRequestInfo) {
			t := time.Now().UTC().String()
			log.Println(t, "wrote all request")
			d.WroteAllRequest.Time = t
		},
		GotFirstResponseByte: func() {
			t := time.Now().UTC().String()
			log.Println(t, "first received response byte")
			d.FirstReceivedResponseByte.Time = t
		},
	}

	return t, d
}

func (c *DataHttpClient) TraceHTTPPost(url string, body []byte) {
	// Create trace struct.
	trace, debug := trace()

	// Prepare request with trace attached to it.
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Fatalln("request error", err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// MAke a request.
	res, err := c.client.Do(req)
	if err != nil {
		log.Fatalln("client error", err)
	}
	defer res.Body.Close()

	// Read response.
	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Print report.
	data, err := json.MarshalIndent(debug, "", "    ")
	fmt.Println(string(data))
	fmt.Println(string(respBody))
}

func (c *DataHttpClient) TraceHTTPGet(url string) {
	// Create trace struct.
	trace, debug := trace()

	// Prepare request with trace attached to it.
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatalln("request error", err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// MAke a request.
	res, err := c.client.Do(req)
	if err != nil {
		log.Fatalln("client error", err)
	}
	defer res.Body.Close()

	// Read response.
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Print report.
	data, err := json.MarshalIndent(debug, "", "    ")
	fmt.Println(string(data))
	fmt.Println(string(body))
}

func (c *DataHttpClient) Post(url string, contentType string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request error: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	// Make a request.
	return c.client.Do(req)
}

func (c *DataHttpClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("request error: %v", err)
	}
	// Make a request.
	return c.client.Do(req)
}
