package usftp

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
)

func Dial(user string, host string, port int, privateKeyPath string, hostKeyCallback ssh.HostKeyCallback) (*ssh.Client, error) {
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
		HostKeyCallback: hostKeyCallback,
	}
	if config.HostKeyCallback == nil {
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	return ssh.Dial("tcp", addr, &config)
}
