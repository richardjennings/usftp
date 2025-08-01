package usftp

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
)

type (
	reader struct {
		r        io.Reader
		rChanMtx sync.Mutex
		rChan    map[uint32]chan Msg
	}
)

func (r *reader) handler(s *Session, ctx context.Context) func() error {
	return func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			default:
				msg, err := s.r.read()
				if err == io.EOF {
					continue
				}
				s.r.rChanMtx.Lock()
				if _, ok := msg.(sequence); ok {
					id := msg.(sequence).id()
					if _, ok := s.r.rChan[id]; !ok {
						s.r.rChan[id] = make(chan Msg)
					}
					s.r.rChan[id] <- msg
				} else {
					s.r.rChan[0] <- msg
				}
				s.r.rChanMtx.Unlock()
			}
		}
	}
}

func (r *reader) read() (Msg, error) {
	p := &packet{}
	read := func(v interface{}) error {
		return binary.Read(r.r, binary.BigEndian, v)
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

func (r *reader) getChan(s uint32) chan Msg {
	r.rChanMtx.Lock()
	defer r.rChanMtx.Unlock()
	if _, ok := r.rChan[s]; !ok {
		r.rChan[s] = make(chan Msg)
	}
	return r.rChan[s]
}

func (r *reader) delChan(s uint32) {
	r.rChanMtx.Lock()
	defer r.rChanMtx.Unlock()
	delete(r.rChan, s)
}
