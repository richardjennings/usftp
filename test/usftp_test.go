package test

import (
	"github.com/richardjennings/usftp"
	"golang.org/x/crypto/ssh"
	"testing"
)

func Test_Connection(t *testing.T) {
	c, err := usftp.Dial("foo", "127.0.0.1", 2222, "./ssh_key")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	s, err := usftp.NewSession(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
}

func clientHelper(t *testing.T) *ssh.Client {
	c, err := usftp.Dial("foo", "127.0.0.1", 2222, "./ssh_key")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func Test_Ls(t *testing.T) {
	c := clientHelper(t)
	defer func() { _ = c.Close() }()
	s, err := usftp.NewSession(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	names, err := s.Ls("/share")
	if err != nil {
		t.Fatal(err)
	}
	expected := 4
	if len(names) != expected {
		t.Errorf("got %d names, expected %d", len(names), expected)
	}
}
