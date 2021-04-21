package mocks

import (
	"github.com/xcaliburne/RemoteAttestations/pkg/httpClient"
	"net/http"
)

type MockHttpClient struct {
	CatchPost func(url string, contentType string, body []byte) (*http.Response, error)
	CatchGet  func(url string) (*http.Response, error)
}

var _ httpClient.HttpClient = (*MockHttpClient)(nil)

func (c *MockHttpClient) Post(url string, contentType string, body []byte) (*http.Response, error) {
	return c.CatchPost(url, contentType, body)
}

func (c *MockHttpClient) Get(url string) (*http.Response, error) {
	return c.CatchGet(url)
}
