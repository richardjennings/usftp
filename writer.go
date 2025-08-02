package usftp

import (
	"bytes"
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
	if err := WriteUint32(buf, l); err != nil {
		return err
	}
	t, err := TypeId(m)
	if err != nil {
		return err
	}
	if err := WriteUint8(buf, t); err != nil {
		return err
	}
	buf.Write(payload)
	_, err = w.w.Write(buf.Bytes())
	return err
}
