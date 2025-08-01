package usftp

import (
	"bytes"
	"encoding/binary"
	"io"
)

type (
	writer struct {
		w io.Writer
	}
)

func (w *writer) write(m Msg) error {
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
	_, err = w.w.Write(buf.Bytes())
	return err
}
