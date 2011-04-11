package authcookie

import (
	"testing"
	"time"
)

func TestEscape(t *testing.T) {
	ss := []string{
		"",
		"~",
		"|",
		"~|",
		"|~",
		"!~",
		"~!",
		"!|",
		"|!",
		"one",
		"one|two",
		"one~two",
		"one~!two",
		"one~!two~~!three|four",
		"one~!two~~~!three~|four",
		"one~|two",
		"~~~!|zoidberg|!~~~",
	}
	for _, s := range ss {
		esc := escape(s)
		unesc, err := unescape(esc)
		if err != nil {
			t.Errorf("unescape: %s", err)
		}
		if s != unesc {
			t.Errorf("wrong escape/unescape"+
				":\n\t orig: %q\n\t  esc: %q\n\tunesc: %q",s, esc, unesc)
		}
	}
}

func TestNew(t *testing.T) {
	good := "hello world|42|f6fa3cab7daff3788eb02095fb470e56ed9084ef5d7a6ffd2fe29ee6929b9880"
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
		t.Errorf("error parsing valid cookie")
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
		"badcookie",
		"bad|cookie",
		"bad|cookie|again",
		"bad|1234567890|f6fa3cab7daff3788eb02095fb470e56ed9084ef5d7a6ffd2fe29ee6929b9880",
		"hello world|43|f6fa3cab7daff3788eb02095fb470e56ed9084ef5d7a6ffd2fe29ee6929b9880",
		"helloworld|42|f6fa3cab7daff3788eb02095fb470e56ed9084ef5d7a6ffd2fe29ee6929b9880",
		"hello world|42|f0fa3cab7daff3788eb02095fb470e56ed9084ef5d7a6ffd2fe29ee6929b9880",
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
