package usftp

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
)

const (
	// The following values are defined for packet types:

	SSH_FXP_INIT           = 1
	SSH_FXP_VERSION        = 2
	SSH_FXP_OPEN           = 3
	SSH_FXP_CLOSE          = 4
	SSH_FXP_READ           = 5
	SSH_FXP_WRITE          = 6
	SSH_FXP_LSTAT          = 7
	SSH_FXP_FSTAT          = 8
	SSH_FXP_SETSTAT        = 9
	SSH_FXP_FSETSTAT       = 10
	SSH_FXP_OPENDIR        = 11
	SSH_FXP_READDIR        = 12
	SSH_FXP_REMOVE         = 13
	SSH_FXP_MKDIR          = 14
	SSH_FXP_RMDIR          = 15
	SSH_FXP_REALPATH       = 16
	SSH_FXP_STAT           = 17
	SSH_FXP_RENAME         = 18
	SSH_FXP_READLINK       = 19
	SSH_FXP_SYMLINK        = 20
	SSH_FXP_STATUS         = 101
	SSH_FXP_HANDLE         = 102
	SSH_FXP_DATA           = 103
	SSH_FXP_NAME           = 104
	SSH_FXP_ATTRS          = 105
	SSH_FXP_EXTENDED       = 200
	SSH_FXP_EXTENDED_REPLY = 201
)

type (
	Session struct {
		s   *ssh.Session
		r   io.Reader
		w   io.Writer
		seq uint32
	}

	// Msg is an Session protocol message
	Msg interface {
		encoding.BinaryMarshaler
		encoding.BinaryUnmarshaler
	}

	// packet
	// All packets transmitted over the secure connection are of the
	// following format:
	//
	//  	uint32             length
	//  	byte               type
	//  	byte[length - 1]   data payload
	//
	packet struct {
		Length  uint32
		Type    byte
		Payload []byte
	}

	// Init
	// When the file transfer protocol starts, it first sends a SSH_FXP_INIT
	// (including its version number) packet to the server.  The server
	// responds with a SSH_FXP_VERSION packet, supplying the lowest of its
	// own and the client's version number.  Both parties should from then
	// on adhere to particular version of the protocol.
	//
	// The SSH_FXP_INIT packet (from client to server) has the following
	// data:
	//
	// 	uint32 version
	// 	<extension data>
	//
	//  The SSH_FXP_VERSION packet (from server to client) has the following
	// data:
	//
	// 	uint32 version
	// 	<extension data>
	//
	// The version number of the protocol specified in this document is 3.
	// The version number should be incremented for each incompatible
	// revision of this protocol.
	//
	//  The extension data in the above packets may be empty, or may be a
	// sequence of
	//
	// 	string extension_name
	// 	string extension_data
	//
	// pairs (both strings MUST always be present if one is, but the
	// `extension_data' string may be of zero length).  If present, these
	// strings indicate extensions to the baseline protocol.  The
	// `extension_name' field(s) identify the name of the extension.  The
	// name should be of the form "name@domain", where the domain is the DNS
	// domain name of the organization defining the extension.  Additional
	// names that are not of this format may be defined later by the IETF.
	// Implementations MUST silently ignore any extensions whose name they
	// do not recognize.
	Init struct {
		Version    uint32
		Extensions []struct {
			Name string
			Data string
		}
	}

	Version struct {
		Version    uint32
		Extensions []struct {
			Name string
			Data string
		}
	}
)

func TypeId(m Msg) (uint8, error) {
	switch m.(type) {
	case *Init:
		return SSH_FXP_INIT, nil
	case *Version:
		return SSH_FXP_VERSION, nil
	default:
		return 0, fmt.Errorf("unhandled msg type: %T", m)
	}
}

func (s *Session) Init() error {
	if err := s.write(&Init{Version: 3}); err != nil {
		return err
	}
	msg, err := s.read()
	if err != nil {
		return err
	}
	if msg, ok := msg.(*Version); ok {
		if msg.Version != 3 {
			return fmt.Errorf("unhandled SFTP version: %d", msg.Version)
		}
	} else {
		return fmt.Errorf("unexpected msg type: %T for Init", msg)
	}
	return nil
}

func (s *Session) Close() error {
	return s.s.Close()
}

func (s *Session) read() (Msg, error) {
	p := &packet{}
	read := func(v interface{}) error {
		return binary.Read(s.r, binary.BigEndian, v)
	}
	if err := read(&p.Length); err != nil {
		return nil, err
	}
	if err := read(&p.Type); err != nil {
		return nil, err
	}
	p.Payload = make([]byte, p.Length-1)
	if err := read(&p.Payload); err != nil {
		return nil, err
	}
	return p.Message()
}

func (s *Session) write(m Msg) error {
	buf := bytes.NewBuffer(nil)
	payload, err := m.MarshalBinary()
	if err != nil {
		return err
	}
	l := uint32(len(payload)) + 1
	if err := binary.Write(buf, binary.BigEndian, l); err != nil {
		return err
	}
	t, err := TypeId(m)
	if err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, t); err != nil {
		return err
	}
	buf.Write(payload)
	_, err = s.w.Write(buf.Bytes())
	return err
}

func (p *packet) Message() (Msg, error) {
	var m Msg
	switch p.Type {
	case SSH_FXP_INIT:
		m = &Init{}
	case SSH_FXP_VERSION:
		m = &Version{}
	default:
		return nil, fmt.Errorf("unknown packet type: %v", p.Type)
	}
	return m, m.UnmarshalBinary(p.Payload)
}

func (i *Init) UnmarshalBinary(b []byte) error {
	return binary.Read(bytes.NewBuffer(b), binary.BigEndian, i.Version)
}
func (i *Init) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.BigEndian, i.Version); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (v *Version) UnmarshalBinary(b []byte) error {
	v.Version = binary.BigEndian.Uint32(b[0:4])
	return nil
}
func (v *Version) MarshalBinary() ([]byte, error) {
	return nil, nil
}
