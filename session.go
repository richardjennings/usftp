package usftp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
)

type (
	Session struct {
		s   *ssh.Session
		r   io.Reader
		w   io.Writer
		seq uint32
	}
)

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
	return p.message()
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

func (s *Session) nextSeq() uint32 {
	s.seq++
	return s.seq
}

func (s *Session) Init() error {
	if err := s.write(&InitReq{Version: 3}); err != nil {
		return err
	}
	msg, err := s.read()
	if err != nil {
		return err
	}
	if msg, ok := msg.(*VersionResp); ok {
		if msg.Version != 3 {
			return fmt.Errorf("unhandled SFTP version: %d", msg.Version)
		}
	} else {
		return fmt.Errorf("unexpected msg type: %T for InitReq", msg)
	}
	return nil
}

func (s *Session) Ls(path string) ([]NameRespFile, error) {
	var names []NameRespFile
	id := s.nextSeq()
	if err := s.write(&OpenDirReq{Id: id, Path: path}); err != nil {
		return nil, err
	}
	var handle string
	// expect SSH_FXP_HANDLE or SSH_FXP_STATUS response
	msg, err := s.read()
	if err != nil {
		return nil, err
	}
	switch msg := msg.(type) {
	case *HandleResp:
		handle = msg.Handle
	case *StatusResp:
		return nil, fmt.Errorf("error: %s", msg.ErrorMessage)
	default:
		return nil, errors.New("unhandled")
	}

	cont := true
	for cont {
		if err := s.write(&ReadDirReq{Id: id, Handle: handle}); err != nil {
			return nil, err
		}
		msg, err = s.read()
		if err != nil {
			return nil, err
		}
		// expect SSH_FXP_NAME or SSH_FXP_STATUS response
		switch msg := msg.(type) {
		case *NameResp:
			names = append(names, msg.Names...)
		case *StatusResp:
			if msg.ErrorCode == SSH_FX_EOF {
				cont = false
				continue
			}
			return nil, fmt.Errorf("error: %s", msg.ErrorMessage)
		default:
			return nil, errors.New("unhandled")
		}
	}
	// SSH_FXP_CLOSE
	if err := s.write(&CloseReq{Id: id, Handle: handle}); err != nil {
		return nil, err
	}
	msg, err = s.read()
	if err != nil {
		return nil, err
	}
	// expect SSH_FXP_STATUS
	switch msg := msg.(type) {
	case *StatusResp:
		if msg.ErrorCode != SSH_FX_OK {
			// there is an error, but is it really our problem ?
		}
	default:
		return nil, errors.New("unhandled")
	}

	return names, nil
}
