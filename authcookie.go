// Package authcookie implements creation and verification of signed
// authentication cookies.
//
// Cookie is a Base64 encoded (using URLEncoding, from RFC 4648) string, which
// consists of concatenation of expiration time, login, and signature:
//
// 	expiration time || login || signature
//
// where expiration time is the number of seconds since Unix epoch UTC
// indicating when this cookie must expire (4 bytes, big-endian, uint32), login
// is a byte string of arbitrary length (at least 1 byte, not null-terminated),
// and signature is 32 bytes of HMAC-SHA256(expiration_time || login, k), where
// k = HMAC-SHA256(expiration_time || login, secret key).
//
// Example:
//
//	secret := []byte("my secret key")
//
//	// Generate cookie valid for 24 hours for user "bender"
//	cookie := authcookie.NewSinceNow("bender", 60*60*24, secret)
//
//	// cookie is now:
//	// Tajh02JlbmRlcskYMxowgwPj5QZ94jaxhDoh3n0Yp4hgGtUpeO0YbMTY
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
// Note that login and expiration time are not encrypted, they are only signed
// and Base64 encoded.
package authcookie

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"os"
	"time"
)

const decodedMinLength = 4 /*expiration*/ + 1 /*login*/ + 32 /*signature*/

// MinLength is the minimum allowed length of cookie string.
//
// It is useful for avoiding DoS attacks with too long cookies: before passing
// a cookie to Parse or Login functions, check that it has length less than the
// [maximum login length allowed in your application] + MinLength.
var MinLength = base64.URLEncoding.EncodedLen(decodedMinLength)

func getSignature(b []byte, secret []byte) []byte {
	keym := hmac.NewSHA256(secret)
	keym.Write(b)
	m := hmac.NewSHA256(keym.Sum())
	m.Write(b)
	return m.Sum()
}

var (
	ErrMalformedCookie = os.NewError("malformed cookie")
	ErrWrongSignature  = os.NewError("wrong cookie signature")
)

// New returns a signed authentication cookie for the given login,
// expiration time in seconds since Unix epoch UTC, and secret key.
// If the login is empty, the function returns an empty string.
func New(login string, expires int64, secret []byte) string {
	if login == "" {
		return ""
	}
	llen := len(login)
	b := make([]byte, llen+4+32)
	// Put expiration time.
	binary.BigEndian.PutUint32(b, uint32(expires))
	// Put login.
	copy(b[4:], []byte(login))
	// Calculate and put signature.
	sig := getSignature([]byte(b[:4+llen]), secret)
	copy(b[4+llen:], sig)
	// Base64-encode.
	cookie := make([]byte, base64.URLEncoding.EncodedLen(len(b)))
	base64.URLEncoding.Encode(cookie, b)
	return string(cookie)
}

// NewSinceNow returns a signed authetication cookie for the given login,
// expiration time in seconds since current time, and secret key.
func NewSinceNow(login string, sec int64, secret []byte) string {
	return New(login, sec+time.Seconds(), secret)
}

// Parse verifies the given cookie with the secret key and returns login and
// expiration time extracted from the cookie. If the cookie fails verification
// or is not well-formed, the function returns an error.
//
// Callers must: 
//
// 1. Check for the returned error and deny access if it's present.
//
// 2. Check the returned expiration time and deny access if it's in the past.
//
func Parse(cookie string, secret []byte) (login string, expires int64, err os.Error) {
	blen := base64.URLEncoding.DecodedLen(len(cookie))
	// Avoid allocation if cookie is too short.
	if blen < decodedMinLength {
		err = ErrMalformedCookie
		return
	}
	b := make([]byte, blen)
	blen, err = base64.URLEncoding.Decode(b, []byte(cookie))
	if err != nil {
		return
	}
	// Decoded length may be different from max length, which
	// we allocated, so check it, and set new length for b.
	if blen < decodedMinLength {
		err = ErrMalformedCookie
		return
	}
	b = b[:blen]

	sig := b[blen-32:]
	data := b[:blen-32]

	realSig := getSignature(data, secret)
	if subtle.ConstantTimeCompare(realSig, sig) != 1 {
		err = ErrWrongSignature
		return
	}
	expires = int64(binary.BigEndian.Uint32(data[:4]))
	login = string(data[4:])
	return
}

// Login returns a valid login extracted from the given cookie and verified
// using the given secret key.  If verification fails or the cookie expired,
// the function returns an empty string.
func Login(cookie string, secret []byte) string {
	l, exp, err := Parse(cookie, secret)
	if err != nil || exp < time.Seconds() {
		return ""
	}
	return l
}
