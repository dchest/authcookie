package authcookie

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	secret := []byte("secret key")
	good := "AAAAKmhlbGxvIHdvcmxk9p6koQvSacAeliAm445i7errSk1NPkYJGYZhF93wG9U="
	c := New("hello world", 42, secret)
	if c != good {
		t.Errorf("expected %q, got %q", good, c)
	}
	// Test empty login
	c = New("", 42, secret)
	if c != "" {
		t.Errorf(`allowed empty login: got %q, expected ""`, c)
	}
}

func TestParse(t *testing.T) {
	// good
	sec := time.Seconds()
	login := "bender"
	key := []byte("another secret key")
	c := New(login, sec, key)
	l, e, err := Parse(c, key)
	if err != nil {
		t.Errorf("error parsing valid cookie: %s", err)
	}
	if l != login {
		t.Errorf("login: expected %q, got %q", login, l)
	}
	if e != sec {
		t.Errorf("expiration: expected %d, got %d", sec, e)
	}
	// bad
	key = []byte("secret key")
	bad := []string{
		"",
		"AAAAKvgQ2I_RGePVk9oAu55q-Valnf__Fx_hlTM-dLwYxXOf",
		"badcookie",
		"AAAAAKmhlbGxvIHdvcmxk9p6koQvSacAeliAm445i7errSk1NPkYJGYZhF93wG9U=",
		"zAAAKmhlbGxvIHdvcmxk9p6koQvSacAeliAm445i7errSk1NPkYJGYZhF93wG9U=",
		"AAAAAKmhlbGxvIHdvcmxk9p6kiQvSacAeliAm445i7errSk1NPkYJGYZhF93wG9U=",
	}
	for _, v := range bad {
		_, _, err := Parse(v, key)
		if err == nil {
			t.Errorf("bad cookie didn't return error: %q", v)
		}
	}
}


func TestLogin(t *testing.T) {
	login := "~~~!|zoidberg|!~~~"
	key := []byte("(:€")
	exp := time.Seconds() + 120
	c := New(login, exp, key)
	l := Login(c, key)
	if l != login {
		t.Errorf("login: expected %q, got %q", login, l)
	}
	c = "no" + c
	l = Login(c, key)
	if l != "" {
		t.Errorf("login expected empty string, got %q", l)
	}
	exp = time.Seconds() - 30
	c = New(login, exp, key)
	l = Login(c, key)
	if l != "" {
		t.Errorf("returned login from expired cookie")
	}
}
