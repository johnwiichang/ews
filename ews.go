package ews

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/Azure/go-ntlmssp"
)

const (
	soapStart = `<?xml version="1.0" encoding="utf-8" ?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
		xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" 
		xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" 
		xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  		<soap:Header>
    		<t:RequestServerVersion Version="Exchange2013_SP1" />
  		</soap:Header>
  		<soap:Body>
`
	soapEnd = `
</soap:Body></soap:Envelope>`
)

type Config struct {
	Dump    bool
	OAuth   bool
	NTLM    bool
	SkipTLS bool

	Transport func(*http.Request) (*http.Response, error)
}

func (c *Config) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.Transport == nil {
		c.Transport = http.DefaultClient.Transport.RoundTrip
	}
	return c.Transport(req)
}

type Client interface {
	SendAndReceive(body []byte) ([]byte, error)
	GetEWSAddr() string
	GetUsername() string
}

type client struct {
	EWSAddr  string
	Username string
	Password string
	config   *Config
}

func (c *client) GetEWSAddr() string {
	return c.EWSAddr
}

func (c *client) GetUsername() string {
	return c.Username
}

func NewClient(ewsAddr, username, password string, config *Config) Client {
	return &client{
		EWSAddr:  ewsAddr,
		Username: username,
		Password: password,
		config:   config,
	}
}

func (c *client) SendAndReceive(body []byte) ([]byte, error) {

	bb := []byte(soapStart)
	bb = append(bb, body...)
	bb = append(bb, soapEnd...)

	req, err := http.NewRequest("POST", c.EWSAddr, bytes.NewReader(bb))
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()
	logRequest(c, req)

	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", "text/xml")

	client := &http.Client{
		Transport: c.config,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	applyConfig(c.config, client)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	logResponse(c, resp)

	if resp.StatusCode != http.StatusOK {
		return nil, NewError(resp)
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return respBytes, err
}

func applyConfig(config *Config, client *http.Client) {
	if config.NTLM {
		client.Transport = ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSNextProto:    map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipTLS},
			},
		}
	}
	if config.OAuth {
		//To get AccessToken from MSAL: https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth and pass it as PASSWORD in any circumstances.
		//BE CAREFUL: 'Main' BRANCH OF GO SUPPORT REPOSITORY github.com/AzureAD/microsoft-authentication-library-for-go MAY NOT UP TO DATE WITH THE PASSAGE REQUIREMENT, USE 'Dev' BRANCH AND PROCEED WITH CAUTION IF YOU ARE IN PRODUCTION.
		client.Transport = bearerNegotiator{config}
	}
	if config.SkipTLS {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
}

func logRequest(c *client, req *http.Request) {
	if c.config != nil && c.config.Dump {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("Request:\n%v\n----\n", string(dump))
	}
}

func logResponse(c *client, resp *http.Response) {
	if c.config != nil && c.config.Dump {
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("Response:\n%v\n----\n", string(dump))
	}
}
