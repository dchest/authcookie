// Package authcookie implements creation and verification of signed
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
// package escape login before signing it, and store it in cookie in escaped
// form: '|' will be "~!", "~" will be "~~".  You don't have to worry about
// this, because Parse and Login unescape it.
//
// Example:
//
//	secret := []byte("my secret key")
//
//	// Generate cookie valid for 24 hours for user "bender"
//	cookie := authcookie.NewSinceNow("bender", 60*60*24, secret)
//
//	// cookie is now:
//	// bender|1302617160|63c9f7146224ba5a0e58e5e51f7392445367eaafe9499426a1170cc2694b3c91	
//	// send it to user's browser..
//	
//	// To authenticate a user later, receive cookie and:
//	login := authcookie.Login(cookie, secret)
//	if login != "" {
//		// access for login granted
//	} else {
//		// access denied
//	}
//
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
	// Avoid allocation if no escape characters found
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
	data := escape(login) + "|" + strconv.Itoa64(expires)
	b := []byte(data)
	keym := hmac.New(sha256.New, secret)
	keym.Write(b)
	m := hmac.New(sha256.New, keym.Sum())
	m.Write(b)
	return data + "|" + hex.EncodeToString(m.Sum())
}

// NewSinceNow returns a signed authetication cookie for the given login,
// expiration time in seconds since current time, and secret key.
// Login must not contain '|' character.
func NewSinceNow(login string, sec int64, secret []byte) string {
	return New(login, sec+time.Seconds(), secret)
}

// Parse verifies the given cookie with the secret key and returns login and
// expiration time extracted from the cookie.  If the cookie fails verification
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
	if len(sig) != sha256.Size {
		err = os.NewError("signature too short")
		return
	}
	b := []byte(p[0] + "|" + p[1])
	keym := hmac.New(sha256.New, secret)
	keym.Write(b)
	m := hmac.New(sha256.New, keym.Sum())
	m.Write(b)
	if subtle.ConstantTimeCompare(m.Sum(), sig) != 1 {
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

// Login returns a valid login extracted from the given cookie and verified
// using the given secret key.  If verification fails or the cookie expired,
// the function returns an empty string.
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
