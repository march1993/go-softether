package mayaqua

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// HTTP_PACK_RAND_SIZE_MAX Maximum size of the random number to be included in the PACK
const (
	HTTP_PACK_RAND_SIZE_MAX = 1000
)

const (
	HTTP_CONTENT_TYPE2 = "application/octet-stream"
	HTTP_CONTENT_TYPE3 = "image/jpeg"
	HTTP_KEEP_ALIVE    = "timeout=15; max=19"
	HTTP_VPN_TARGET    = "/vpnsvc/vpn.cgi"
	HTTP_VPN_TARGET2   = "/vpnsvc/connect.cgi"
)

// HttpClientRecv http client recv
func HttpClientRecv(s *Sock, req *http.Request) (*Pack, error) {
	if res, err := http.ReadResponse(s.reader, req); nil != err {
		return nil, err
	} else {
		defer res.Body.Close()
		if res.ContentLength == 0 ||
			res.Proto != "HTTP/1.1" ||
			res.StatusCode != http.StatusOK ||
			res.Header.Get("Content-Type") != HTTP_CONTENT_TYPE2 ||
			res.ContentLength > MAX_PACK_SIZE {
			return nil, ERR_SERVER_IS_NOT_VPN
		}
		buf := make([]byte, int(res.ContentLength))
		if _, err := io.ReadFull(res.Body, buf); nil != err {
			return nil, err
		} else {
			r := bytes.NewReader(buf)
			return ReadPack(r)
		}
	}
}

// HttpClientSend http client send
func HttpClientSend(s *Sock, p *Pack) (*http.Request, error) {
	p.CreateDummyValue()

	b, err := p.ToBuf()
	if nil != err {
		return nil, err
	}

	req := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path: HTTP_VPN_TARGET,
		},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       s.RemoteIP,
		Body:       ioutil.NopCloser(bytes.NewReader(b)),
		Header: http.Header{
			"Date":         []string{time.Now().Local().String()},
			"Keep-Alive":   []string{HTTP_KEEP_ALIVE},
			"Content-Type": []string{HTTP_CONTENT_TYPE2},
		},
		ContentLength: int64(len(b)),
	}

	return req, req.Write(s)

}
