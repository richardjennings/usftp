package usftp

import (
	"context"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"io"
	"sort"
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

func (s *Session) Ls(path string) ([]*NameRespFile, error) {
	var names []*NameRespFile
	id := s.nextSeq()
	read := s.r.getChan(id)
	defer s.r.delChan(id)
	if err := s.w.write(&OpenDirReq{Header: Header{Id: id}, Path: path}); err != nil {
		return nil, err
	}
	msg := <-read
	var handle string
	handleResp, statusResp, err := s.handleOrStatusResp(msg)
	switch true {
	case err != nil:
		return nil, err
	case handleResp != nil:
		handle = handleResp.Handle
	case statusResp != nil:
		return nil, fmt.Errorf("error: %s", statusResp.ErrorMessage)
	}
	cont := true
	for cont {
		nameResp, statusResp, err := s.readDirReq(id, read, handle)
		switch true {
		case err != nil:
			return nil, err
		case nameResp != nil:
			names = append(names, nameResp.Names...)
		case statusResp != nil:
			if statusResp.ErrorCode == SSH_FX_EOF {
				cont = false
				continue
			}
			return nil, fmt.Errorf("error: %s", statusResp.ErrorMessage)
		}
	}
	_ = s.CloseReq(id, read, handle)
	sort.Slice(names, func(i, j int) bool {
		return names[i].Filename < names[j].Filename
	})
	return names, nil
}

func (s *Session) Find(path string) ([]*NameRespFile, error) {
	return s.find(path, "")
}

func (s *Session) find(path string, parent string) ([]*NameRespFile, error) {
	if parent != "" {
		path = fmt.Sprintf("%s/%s", parent, path)
	}
	files, err := s.Ls(path)
	if err != nil {
		return nil, err
	}
	for i, file := range files {
		if file.Filename == "." || file.Filename == ".." {
			continue
		}
		if file.Attrs.Permissions.IsDir() {
			childFiles, err := s.find(file.Filename, path)
			if err != nil {
				return nil, err
			}
			files[i].Children = childFiles
		}
	}
	return files, nil
}

func (s *Session) Get(from string, out io.Writer) error {
	id := s.nextSeq()
	read := s.r.getChan(id)
	defer s.r.delChan(id)
	handle, err := s.OpenReq(id, read, from)
	if err != nil {
		return err
	}
	defer func() { _ = s.CloseReq(id, read, handle) }()
	// how much to read at a time ?
	//
	// https://github.com/openssh/openssh-portable/blob/master/sftp-common.h#L29
	// /* Maximum packet that we are willing to send/accept */
	//    #define SFTP_MAX_MSG_LENGTH	(256 * 1024)
	cont := true
	offset := uint64(0)
	len := uint32(255 * 1024)
	for cont {
		b, err := s.ReadReq(id, read, handle, offset, len)
		if err != nil {
			if err == io.EOF {
				cont = false
			} else {
				return err
			}
		}
		_, err = out.Write(b)
		if err != nil {
			return err
		}
		offset += uint64(len)
	}

	return nil
}

func (s *Session) ReadReq(id uint32, read chan Msg, handle string, offset uint64, len uint32) ([]byte, error) {
	if err := s.w.write(&ReadReq{Header: Header{Id: id}, Handle: handle, Offset: offset, Len: len}); err != nil {
		return nil, err
	}
	msg := <-read
	switch msg := msg.(type) {
	case *DataResp:
		return msg.Data, nil
	case *StatusResp:
		if msg.ErrorCode == SSH_FX_EOF {
			return nil, io.EOF
		}
		if msg.ErrorCode == SSH_FX_OK {
			return nil, io.EOF
		} else {
			return nil, fmt.Errorf("error: %s", msg.ErrorMessage)
		}
	default:
		return nil, fmt.Errorf("unhandled message type %T", msg)
	}
}

func (s *Session) CloseReq(id uint32, read chan Msg, handle string) error {
	if err := s.w.write(&CloseReq{Header: Header{Id: id}, Handle: handle}); err != nil {
		return err
	}
	msg := <-read
	switch msg := msg.(type) {
	case *StatusResp:
		if msg.ErrorCode != SSH_FX_OK {
			// there is an error, but is it really our problem ?
		}
	default:
		return fmt.Errorf("unhandled message type %T", msg)
	}
	return nil
}

func (s *Session) OpenReq(id uint32, read chan Msg, path string) (string, error) {
	if err := s.w.write(&OpenReq{Header: Header{Id: id}, Filename: path, Pflags: SSH_FXF_READ}); err != nil {
		return "", err
	}
	msg := <-read
	var handle string
	handleResp, statusResp, err := s.handleOrStatusResp(msg)
	switch true {
	case err != nil:
		return "", err
	case handleResp != nil:
		handle = handleResp.Handle
	case statusResp != nil:
		return "", fmt.Errorf("error: %s", statusResp.ErrorMessage)
	}
	return handle, nil
}

func (s *Session) readDirReq(id uint32, read chan Msg, handle string) (*NameResp, *StatusResp, error) {
	if err := s.w.write(&ReadDirReq{Header: Header{Id: id}, Handle: handle}); err != nil {
		return nil, nil, err
	}
	msg := <-read
	nameResp, statusResp, err := s.nameOrStatusResp(msg)
	switch true {
	case err != nil:
		return nil, nil, err
	case nameResp != nil:
		return nameResp, nil, nil
	case statusResp != nil:
		return nil, statusResp, nil
	default:
		return nil, nil, fmt.Errorf("unhandled message type %T", msg)
	}
}

func (s *Session) nameOrStatusResp(msg Msg) (*NameResp, *StatusResp, error) {
	switch msg := msg.(type) {
	case *NameResp:
		return msg, nil, nil
	case *StatusResp:
		return nil, msg, nil
	default:
		return nil, nil, fmt.Errorf("unhandled message type %T", msg)
	}
}

func (s *Session) handleOrStatusResp(msg Msg) (*HandleResp, *StatusResp, error) {
	switch msg := msg.(type) {
	case *HandleResp:
		return msg, nil, nil
	case *StatusResp:
		return nil, msg, nil
	default:
		return nil, nil, fmt.Errorf("unhandled message type %T", msg)
	}
}
