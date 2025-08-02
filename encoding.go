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
