# USFTP

An SFTP client library with minimal dependencies.

With reference to https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02


## Use

```go
package main

import (
	"github.com/richardjennings/usftp"
	"os"
)

func main() {
	c, _ := usftp.Dial("user", "host", 22, "/path/to/key", nil)
	defer func() { _ = c.Close() }()
	s, _ := usftp.NewSession(c)
	defer func() { _ = s.Close() }()
	files, _ := s.Find("/share")
	_ = files
	_ = s.Get("share/file.txt", os.Stdout)
}

```