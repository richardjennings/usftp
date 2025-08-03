package test

import (
	"bytes"
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
	{
		expected := 4
		if len(names) != expected {
			t.Errorf("got %d names, expected %d", len(names), expected)
		}
	}

	m := make(map[string]usftp.FileMode)
	for _, name := range names {
		m[name.Filename] = name.Attrs.Permissions
	}
	if !m["."].IsDir() {
		t.Errorf("expected . to be a directory")
	}
	if m["."].IsRegular() {
		t.Errorf("expected . to be a directory")
	}

	actual := m["."].String()
	expected := "drwxr-xr-x"
	if actual != expected {
		t.Errorf("got %s, expected %s", actual, expected)
	}

	if (m["file1.txt"]).IsDir() {
		t.Errorf("expected file.txt to be a file")
	}
	if !(m["file1.txt"]).IsRegular() {
		t.Errorf("expected file.txt to be a file")
	}
}

func Test_Get(t *testing.T) {
	c := clientHelper(t)
	defer func() { _ = c.Close() }()
	s, err := usftp.NewSession(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	w := bytes.NewBuffer(nil)
	if err := s.Get("/share/file1.txt", w); err != nil {
		t.Fatal(err)
	}
	if w.String() != "a" {
		t.Errorf("got %q, expected %q", w.String(), "a")
	}
}
