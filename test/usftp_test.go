package test

import (
	"github.com/richardjennings/usftp"
	"testing"
)

func TestConnection(t *testing.T) {
	c, err := usftp.NewClient("foo", "127.0.0.1", 2222, "./ssh_key")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
}
