package usftp

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
)

type (
	Client struct {
		conn *ssh.Client
	}
)

func NewClient(user string, host string, port int, privateKeyPath string) (*Client, error) {
	b, err := os.ReadFile(privateKeyPath)
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, err
	}
	auths := []ssh.AuthMethod{
		ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return []ssh.Signer{signer}, nil
		}),
	}
	config := ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // @todo handle properly
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		return nil, err
	}

	c := &Client{
		conn: conn,
	}

	return c, err
}

func (c *Client) NewSession() (*Session, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return nil, err
	}
	if err := session.RequestSubsystem("sftp"); err != nil {
		return nil, err
	}
	w, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	r, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	s := &Session{
		seq: 1,
		s:   session,
		r:   r,
		w:   w,
	}
	err = s.Init()
	return s, err
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
