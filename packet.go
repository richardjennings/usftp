package usftp

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
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

const (
	// Status Codes for SSH_FXP_STATUS

	SSH_FX_OK                = 0
	SSH_FX_EOF               = 1
	SSH_FX_NO_SUCH_FILE      = 2
	SSH_FX_PERMISSION_DENIED = 3
	SSH_FX_FAILURE           = 4
	SSH_FX_BAD_MESSAGE       = 5
	SSH_FX_NO_CONNECTION     = 6
	SSH_FX_CONNECTION_LOST   = 7
	SSH_FX_OP_UNSUPPORTED    = 8
)

const (
	// Attribute Flag Masks

	SSH_FILEXFER_ATTR_SIZE        = 0x00000001
	SSH_FILEXFER_ATTR_UIDGID      = 0x00000002
	SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
	SSH_FILEXFER_ATTR_ACMODTIME   = 0x00000008
	SSH_FILEXFER_ATTR_EXTENDED    = 0x80000000
)

type (

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

	// Msg is an Session protocol message
	Msg interface {
		encoding.BinaryMarshaler
		encoding.BinaryUnmarshaler
	}

	// InitReq
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
	InitReq struct {
		Version    uint32
		Extensions []struct {
			Name string
			Data string
		}
	}

	VersionResp struct {
		Version    uint32
		Extensions []struct {
			Name string
			Data string
		}
	}

	OpenDirReq struct {
		Id   uint32
		Path string
	}

	ReadDirReq struct {
		Id     uint32
		Handle string
	}

	HandleResp struct {
		Id     uint32
		Handle string
	}

	StatusResp struct {
		Id           uint32
		ErrorCode    uint32
		ErrorMessage string
		LanguageTag  string
	}
	NameResp struct {
		Id    uint32
		Count uint32
		Names []NameRespFile
	}
	NameRespFile struct {
		Filename string
		Longname string
		Attrs    Attrs
	}
	CloseReq struct {
		Id     uint32
		Handle string
	}

	Attrs struct {
		Size          uint64
		Uid           uint32
		Gid           uint32
		Permissions   uint32
		Atime         uint32
		Mtime         uint32
		ExtendedCount uint32
		ExtendedType  string
		ExtendedData  string
	}
)

func (p *packet) message() (Msg, error) {
	var m Msg
	switch p.Type {
	case SSH_FXP_INIT:
		m = &InitReq{}
	case SSH_FXP_VERSION:
		m = &VersionResp{}
	case SSH_FXP_OPENDIR:
		m = &OpenDirReq{}
	case SSH_FXP_STATUS:
		m = &StatusResp{}
	case SSH_FXP_HANDLE:
		m = &HandleResp{}
	case SSH_FXP_READDIR:
		m = &ReadDirReq{}
	case SSH_FXP_NAME:
		m = &NameResp{}
	default:
		return nil, fmt.Errorf("unknown packet type: %v", p.Type)
	}
	return m, m.UnmarshalBinary(p.Payload)
}

func TypeId(m Msg) (uint8, error) {
	switch m.(type) {
	case *InitReq:
		return SSH_FXP_INIT, nil
	case *VersionResp:
		return SSH_FXP_VERSION, nil
	case *OpenDirReq:
		return SSH_FXP_OPENDIR, nil
	case *ReadDirReq:
		return SSH_FXP_READDIR, nil
	case *CloseReq:
		return SSH_FXP_CLOSE, nil
	default:
		return 0, fmt.Errorf("unhandled msg type: %T", m)
	}
}

func (i *InitReq) UnmarshalBinary(b []byte) error {
	return binary.Read(bytes.NewBuffer(b), binary.BigEndian, i.Version)
}
func (i *InitReq) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.BigEndian, i.Version); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (v *VersionResp) UnmarshalBinary(b []byte) error {
	v.Version = binary.BigEndian.Uint32(b[0:4])
	return nil
}
func (v *VersionResp) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (r *OpenDirReq) UnmarshalBinary(b []byte) error {
	return nil
}
func (r *OpenDirReq) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.BigEndian, r.Id); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(len([]rune(r.Path)))); err != nil {
		return nil, err
	}
	buf.WriteString(r.Path)
	return buf.Bytes(), nil
}

func (r *ReadDirReq) UnmarshalBinary(b []byte) error {
	return nil
}
func (r *ReadDirReq) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.BigEndian, r.Id); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(len(r.Handle))); err != nil {
		return nil, err
	}
	buf.Write([]byte(r.Handle))
	return buf.Bytes(), nil
}

func (r *HandleResp) UnmarshalBinary(b []byte) error {
	r.Id = binary.BigEndian.Uint32(b[0:4])
	l := binary.BigEndian.Uint32(b[4:8])
	r.Handle = string(b[8 : 8+l])
	return nil
}
func (r *HandleResp) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (r *CloseReq) UnmarshalBinary(b []byte) error {
	return nil
}
func (r *CloseReq) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.BigEndian, r.Id); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(len(r.Handle))); err != nil {
		return nil, err
	}
	buf.Write([]byte(r.Handle))
	return buf.Bytes(), nil
}

func (r *StatusResp) UnmarshalBinary(b []byte) error {
	r.Id = binary.BigEndian.Uint32(b[0:4])
	r.ErrorCode = binary.BigEndian.Uint32(b[4:8])
	l := binary.BigEndian.Uint32(b[8:12])
	msg := b[12 : 12+l]
	r.ErrorMessage = string(msg)
	return nil
}
func (r *StatusResp) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (r *NameResp) UnmarshalBinary(b []byte) error {
	r.Id = binary.BigEndian.Uint32(b[0:4])
	r.Count = binary.BigEndian.Uint32(b[4:8])
	os := uint32(8) // offset
	//
	flags := binary.BigEndian.Uint32(b[0:4])
	size := SSH_FILEXFER_ATTR_SIZE&flags != 0
	uidguid := SSH_FILEXFER_ATTR_UIDGID&flags != 0
	permissions := SSH_FILEXFER_ATTR_PERMISSIONS&flags != 0
	acmodtime := SSH_FILEXFER_ATTR_ACMODTIME&flags != 0
	extended := SSH_FILEXFER_ATTR_EXTENDED&flags != 0
	size = false

	for i := uint32(0); i < r.Count; i++ {
		v := NameRespFile{}
		fnLen := binary.BigEndian.Uint32(b[os : os+4])
		os += 4
		v.Filename = string(b[os : os+fnLen])
		os = os + fnLen
		lnLen := binary.BigEndian.Uint32(b[os : os+4])
		os += 4
		v.Longname = string(b[os : os+lnLen])
		os += lnLen

		if size {
			v.Attrs.Size = binary.BigEndian.Uint64(b[os : os+8])

		}
		os += 8

		if uidguid {
			// @todo
		}
		os += 8

		if permissions {
			// @todo
		}
		os += 4

		if acmodtime {
			// @todo
		}
		os += 8

		if extended {
			// @todo
		}
		os += 4

		r.Names = append(r.Names, v)
	}

	return nil
}
func (r *NameResp) MarshalBinary() ([]byte, error) {
	return nil, nil
}
