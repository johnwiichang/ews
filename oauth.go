package ews

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type bearerNegotiator struct{ http.RoundTripper }

// C# Code Ref: https://github.com/OfficeDev/ews-managed-api/blob/master/Credentials/OAuthCredentials.cs
func (b bearerNegotiator) RoundTrip(req *http.Request) (res *http.Response, err error) {
	rt := b.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
	}
	u, p := b.authheader(req.Header.Get("Authorization"))
	if len(u) == 0 {
		//If it is not a simple auth, just run it as usual
		return rt.RoundTrip(req)
	}
	//Set bearer header info
	req.Header.Set("Authorization", "Bearer "+p)
	//Set anchor mailbox info
	req.Header.Set("X-AnchorMailbox", u)
	//Read the body and add soap:Header element
	if bin, _ := io.ReadAll(req.Body); len(bin) > 0 {
		//IMPORTANT: REMOVE THIS PART YOU WILL MEET:
		//ExchangeImpersonation SOAP header must be present for this type of OAuth token.
		//Issue on stackoverflow: https://stackoverflow.com/questions/56148996/error-exchangeimpersonation-soap-header-must-be-present-for-this-type-of-oauth
		//Manual by Microsoft: https://learn.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2010/bb204088(v=exchg.140)
		bin = bytes.Replace(bin, []byte(`<t:RequestServerVersion Version="Exchange2013_SP1" />`), []byte(fmt.Sprintf(`<t:ExchangeImpersonation><t:ConnectingSID><t:PrimarySmtpAddress>%s</t:PrimarySmtpAddress></t:ConnectingSID></t:ExchangeImpersonation>`, u)), 1)
		req.Body = io.NopCloser(bytes.NewReader(bin))
		//Update content-length information.
		req.ContentLength = int64(len(bin))
	}
	return rt.RoundTrip(req)
}

func (bearerNegotiator) authheader(auth string) (u, p string) {
	if !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		return
	}
	authStr, _ := base64.StdEncoding.DecodeString(auth[6:])
	var idx = bytes.LastIndex(authStr, []byte{':'})
	if idx != -1 {
		u, p = string(authStr[:idx]), string(authStr[idx+1:])
	}
	return
}
