package usftp

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"sync/atomic"
)

type (
	Session struct {
		s      *ssh.Session
		r      reader
		w      writer
		ctx    context.Context
		cancel context.CancelFunc
		seq    uint32
		errors []error
	}
)

func NewSession(c *ssh.Client) (*Session, error) {
	session, err := c.NewSession()
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

	ctx, cancel := context.WithCancel(context.Background())

	s := &Session{
		s:      session,
		r:      reader{r: r, rChan: make(map[uint32]chan Msg)},
		w:      writer{w: w},
		ctx:    ctx,
		cancel: cancel,
	}

	go func() {
		eg, ctx := errgroup.WithContext(s.ctx)
		eg.Go(s.r.handler(s, ctx))
		_ = eg.Wait()
	}()

	err = s.init()
	return s, err
}

func (s *Session) Errors() []error {
	return s.errors
}

func (s *Session) Close() error {
	s.cancel()
	return s.s.Close()
}

func (s *Session) nextSeq() uint32 {
	atomic.AddUint32(&s.seq, 1)
	return s.seq
}

func (s *Session) init() error {
	defer s.r.delChan(0)
	if err := s.w.write(&InitReq{Version: 3}); err != nil {
		return err
	}
	c := s.r.getChan(0)
	msg := <-c
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
	read := s.r.getChan(id)
	defer s.r.delChan(id)
	if err := s.w.write(&OpenDirReq{Header: Header{Id: id}, Path: path}); err != nil {
		return nil, err
	}
	var handle string
	msg := <-read
	// expect SSH_FXP_HANDLE or SSH_FXP_STATUS response
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
		if err := s.w.write(&ReadDirReq{Header: Header{Id: id}, Handle: handle}); err != nil {
			return nil, err
		}
		msg = <-read
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
	if err := s.w.write(&CloseReq{Header: Header{Id: id}, Handle: handle}); err != nil {
		return nil, err
	}
	msg = <-read

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
