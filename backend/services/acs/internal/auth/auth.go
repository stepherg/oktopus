package auth

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type myjar struct {
	jar map[string][]*http.Cookie
}

func (p *myjar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.jar[u.Host] = cookies
}

func (p *myjar) Cookies(u *url.URL) []*http.Cookie {
	return p.jar[u.Host]
}

func Auth(username string, password string, url string) (bool, error) {
	client := &http.Client{Timeout: time.Second * 1}
	jar := &myjar{}
	jar.jar = make(map[string][]*http.Cookie)
	client.Jar = jar
	var req *http.Request
	var resp *http.Response
	var err error

	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Connection", "keep-alive")
	req.Header.Del("Accept-Encoding")

	resp, err = client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case 401:
		var authorization = DigestAuthParams(resp)
		realmHeader := authorization["realm"]
		qopHeader := authorization["qop"]
		nonceHeader := authorization["nonce"]
		opaqueHeader := authorization["opaque"]
		realm := realmHeader

		uri := "/"
		if surl := strings.Split(url, "/"); len(surl) == 4 {
			uri = "/" + surl[3]
		}

		// A1
		h := md5.New()
		A1 := fmt.Sprintf("%s:%s:%s", username, realm, password)
		_, _ = io.WriteString(h, A1)
		HA1 := fmt.Sprintf("%x", h.Sum(nil))

		// A2
		h = md5.New()
		A2 := fmt.Sprintf("GET:%s", uri)
		_, _ = io.WriteString(h, A2)
		HA2 := fmt.Sprintf("%x", h.Sum(nil))

		// response
		cnonce := RandomKey()
		response := H(strings.Join([]string{HA1, nonceHeader, "00000001", cnonce, qopHeader, HA2}, ":"))

		// now make header
		AuthHeader := fmt.Sprintf(`Digest username="%s",realm="%s",nonce="%s",uri="%s",qop=%s,nc=00000001,cnonce="%s",response="%s",opaque="%s",algorithm=MD5`,
			username, realmHeader, nonceHeader, uri, qopHeader, cnonce, response, opaqueHeader)
		req.Header.Set("Authorization", AuthHeader)

		resp, err = client.Do(req)
		if err != nil {
			return false, err
		}

		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode == 401 {
			return false, fmt.Errorf("authentication error")
		}

		return true, err
	case 200:
		return true, err
	}

	return false, fmt.Errorf("response status code not expected")
}

/*
Parse Authorization header from the http.Request. Returns a map of
auth parameters or nil if the header is not a valid parsable Digest
auth header.
*/
func DigestAuthParams(r *http.Response) map[string]string {
	s := strings.SplitN(r.Header.Get("Www-Authenticate"), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	result := map[string]string{}
	for _, kv := range strings.Split(s[1], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.Trim(parts[0], "\" ")] = strings.Trim(parts[1], "\" ")
	}
	return result
}

func RandomKey() string {
	k := make([]byte, 12)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		bytes += n
	}
	return base64.StdEncoding.EncodeToString(k)
}

/*
H function for MD5 algorithm (returns a lower-case hex MD5 digest)
*/
func H(data string) string {
	digest := md5.New()
	digest.Write([]byte(data))
	return fmt.Sprintf("%x", digest.Sum(nil))
}
