package test

import (
	"bytes"
	"github.com/richardjennings/usftp"
	"golang.org/x/crypto/ssh"
	"testing"
)

func Test_Connection(t *testing.T) {
	c, err := usftp.Dial("foo", "127.0.0.1", 2222, "./ssh_key", nil)
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
	c, err := usftp.Dial("foo", "127.0.0.1", 2222, "./ssh_key", nil)
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

func Test_Find(t *testing.T) {
	c := clientHelper(t)
	defer func() { _ = c.Close() }()
	s, err := usftp.NewSession(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	files, err := s.Find("/share")
	if err != nil {
		t.Fatal(err)
	}
	if files[2].Filename != "dir" {
		t.Errorf("got %q, expected %q", files[2].Filename, "dir")
	}
	if len(files[2].Children) != 4 {
		t.Fatalf("expected %d children, got %d", 4, len(files[2].Children))
	}
	if files[2].Children[3].Filename != "file2.txt" {
		t.Errorf("got %q, expected %q", files[2].Children[3].Filename, "file2.txt")
	}
	if files[2].Children[2].Filename != "dir2" {
		t.Errorf("got %q, expected %q", files[2].Children[2].Filename, "dir2")
	}
	if len(files[2].Children[2].Children) != 3 {
		t.Fatalf("expected %d children, got %d", 3, len(files[2].Children[2].Children))
	}
	if files[2].Children[2].Children[2].Filename != "file3.txt" {
		t.Errorf("got %q, expected %q", files[2].Children[2].Children[2].Filename, "file3.txt")
	}
}

func Test_Walk_UnseenFileVisitor(t *testing.T) {
	c := clientHelper(t)
	defer func() { _ = c.Close() }()
	s, err := usftp.NewSession(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	seen := map[string]*usftp.NameRespFile{
		"/share/file1.txt":     {Attrs: usftp.Attrs{Size: 1}},
		"/share/dir/file2.txt": {Attrs: usftp.Attrs{Size: 1}},
	}
	v := usftp.NewUnseenFileVisitor(seen, []string{})
	if err := s.Walk("/share", v); err != nil {
		t.Fatal(err)
	}
	if len(v.Files()) != 1 {
		t.Fatalf("expected 1 file, got %d", len(v.Files()))
	}
	expectedPath := "/share/dir/dir2"
	if v.Files()[0].Path != expectedPath {
		t.Fatalf("expected %q, got %q", expectedPath, v.Files()[0].Path)
	}
	expectedName := "file3.txt"
	if v.Files()[0].Filename != expectedName {
		t.Fatalf("expected %q, got %q", expectedName, v.Files()[0].Filename)
	}
}
