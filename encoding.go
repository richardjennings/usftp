package usftp

import (
	"encoding/binary"
	"io"
)

func Uint32(b []byte) (uint32, []byte) {
	v := binary.BigEndian.Uint32(b)
	return v, b[4:]
}

func Uint64(b []byte) (uint64, []byte) {
	v := binary.BigEndian.Uint64(b)
	return v, b[8:]
}

func String(b []byte) (string, []byte) {
	l, b := Uint32(b)
	return string(b[0:l]), b[l:]
}

func WriteUint64(w io.Writer, v uint64) error {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	_, err := w.Write(b)
	return err
}

func WriteUint32(w io.Writer, v uint32) error {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	_, err := w.Write(b)
	return err
}

func WriteUint8(w io.Writer, v uint8) error {
	b := []byte{v}
	_, err := w.Write(b)
	return err
}

func WriteString(w io.Writer, v string) error {
	if err := WriteUint32(w, uint32(len(v))); err != nil {
		return err
	}
	_, err := w.Write([]byte(v))
	return err
}
