package authcookie

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	good := "AAAAAAAAACpoZWxsbyB3b3JsZGVALSOGOVVAdyTB0vn84OQW4A3jBOiwW2Leyw-SrUCq"
	c := New("hello world", 42, []byte("secret key"))
	if c != good {
		t.Errorf("expected %q, got %q", good, c)
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
		"badcookie",
		"AAAAAAAAACpoZWxsbyB3b3JsZGVALSOGOVVAdyTB0vn84OQW4A3jBOiwW2Leyw-SrUC",
		"bAAAAAAAAACpoZWxsbyB3b3JsZGVALSOGOVVAdyTB0vn84OQW4A3jBOiwW2Leyw-SrUCq",
		"zAAAAAAAACpoZWxsbyB3b3JsZGVALSOGOVVAdyTB0vn84OQW4A3jBOiwW2Leyw-SrUCq",
		"AAAAAAAAACpoZWxsbyB3b3JsZGbALSOGOVVAdyTB0vn84OQW4A3jBOiwW2Leyw-SrUCq",
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
