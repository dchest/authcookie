// Package authcookie implements creation and validation of signed
// authentication cookies.
//
// Cookie format:
//
// 	login|expiration_time|signature
//
// where:
//
// 	signature=HMAC-SHA256(login|expiration_time, k)
// 	where k=HMAC-SHA256(login|expiration_time, sk)
// 	and sk=secret key
//
// Login is a plain-text string, expiration time is a decimal string, signature
// is a hex-encoded string.
//
// Because character '|' is used as a separator in cookie, functions in this
// package escape login before signing it and store it in cookie in escaped
// form: '|' will be "~!", "~" will be "~~".  You don't have to worry about
// this, because Parse and Login unescape it.
package authcookie

import (
	"fmt"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"
	"utf8"
)

func escape(s string) string {
	s = strings.Replace(s, "~", "~~", -1)
	s = strings.Replace(s, "|", "~!", -1)
	return s
}

func unescape(s string) (string, os.Error) {
	// Avoid allocations if no escape characters found
	if strings.IndexRune(s, '~') < 0 {
		return s, nil
	}

	out := make([]byte, len(s))
	outp := 0
	sp := 0
	for {
		i := strings.IndexRune(s[sp:], '~')
		if i < 0 {
			outp += copy(out[outp:], s[sp:])
			break
		}
		if i >= len(s)-1 {
			return "", os.NewError("malformed escape string")
		}
		cp := copy(out[outp:], s[sp:sp+i])
		sp += cp
		outp += cp
		rune, _ := utf8.DecodeRuneInString(s[sp+1:])
		switch rune {
		case '~':
			out[outp] = '~'
		case '!':
			out[outp] = '|'
		default:
			return "", fmt.Errorf("unknown escape sequence: ~%c", rune)
		}
		sp += 2
		outp++
	}
	return string(out[:outp]), nil
}

// New returns a signed authentication cookie for the given login,
// expiration time in seconds since Unix epoch UTC, and secret key.
// Login must not contain '|' character.
func New(login string, expires int64, secret []byte) string {
	val := escape(login) + "|" + strconv.Itoa64(expires)
	b := []byte(val)

	m1 := hmac.New(sha256.New, secret)
	m1.Write(b)
	k := m1.Sum()

	m2 := hmac.New(sha256.New, k)
	m2.Write(b)
	sig := m2.Sum()

	return val + "|" + hex.EncodeToString(sig)
}

// NewSinceNow returns a signed authetication cookie for the given login,
// expiration time in seconds since current time, and secret key.
// Login must not contain '|' character.
func NewSinceNow(login string, sec int64, secret []byte) string {
	return New(login, sec+time.Seconds(), secret)
}

// Parse validates the given cookie with the secret key and returns login and
// expiration time extracted from the cookie.  If the cookie fails validation
// or is not well-formed, the function returns an error.
//
// Callers must: 
//
// 1. Check for the returned error and deny access if it's present.
//
// 2. Check the returned expiration time and deny access if it's in the past.
//
func Parse(cookie string, secret []byte) (login string, expires int64, err os.Error) {
	p := strings.FieldsFunc(cookie, func(c int) bool { return c == '|' })
	if len(p) != 3 {
		err = os.NewError("malformed cookie")
		return
	}
	sig, err := hex.DecodeString(p[2])
	if err != nil {
		return
	}
	if len(sig) != 32 {
		err = os.NewError("signature too short")
		return
	}
	val := p[0] + "|" + p[1]
	b := []byte(val)

	m1 := hmac.New(sha256.New, secret)
	m1.Write(b)
	k := m1.Sum()

	m2 := hmac.New(sha256.New, k)
	m2.Write(b)
	if subtle.ConstantTimeCompare(m2.Sum(), sig) != 1 {
		err = os.NewError("wrong cookie signature")
		return
	}
	expires, err = strconv.Atoi64(p[1])
	if err != nil {
		return
	}
	login, err = unescape(p[0])
	return
}

// Login returns a valid login extracted from the given cookie and validated
// using the given secret key.  If validation fails or the cookie expired, the
// functions returns an empty string.
func Login(cookie string, secret []byte) string {
	l, exp, err := Parse(cookie, secret)
	if err != nil {
		return ""
	}
	if exp < time.Seconds() {
		return ""
	}
	return l
}
