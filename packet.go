package usftp

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
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

const (
	// SSH_FXF_READ Open the file for reading.
	SSH_FXF_READ = 0x00000001

	// SSH_FXF_WRITE Open the file for writing.  If both this and SSH_FXF_READ
	// are specified, the file is opened for both reading and writing.
	SSH_FXF_WRITE = 0x00000002

	// SSH_FXF_APPEND Force all writes to append data at the end of the file.
	SSH_FXF_APPEND = 0x00000004

	// SSH_FXF_CREAT If this flag is specified, then a new file will be created
	// if one does not already exist (if O_TRUNC is specified, the new file will
	// be truncated to zero length if it previously exists).
	SSH_FXF_CREAT = 0x00000008

	// SSH_FXF_TRUNC Forces an existing file with the same name to be truncated
	// to zero length when creating a file by specifying SSH_FXF_CREAT.
	// SSH_FXF_CREAT MUST also be specified if this flag is used.
	SSH_FXF_TRUNC = 0x00000010

	// SSH_FXF_EXCL Causes the request to fail if the named file already exists.
	// SSH_FXF_CREAT MUST also be specified if this flag is used.
	SSH_FXF_EXCL = 0x00000020
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

	// sequence interface provides a sequence id
	sequence interface {
		id() uint32
	}

	// Header embeds a sequence implementation in messages that required one
	Header struct {
		Id uint32
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
		Header
		Path string
	}

	ReadDirReq struct {
		Header
		Handle string
	}

	HandleResp struct {
		Header
		Handle string
	}

	StatusResp struct {
		Header
		ErrorCode    uint32
		ErrorMessage string
		LanguageTag  string
	}
	NameResp struct {
		Header
		Count uint32
		Names []NameRespFile
	}
	NameRespFile struct {
		Filename string
		Longname string
		Attrs    Attrs
	}
	CloseReq struct {
		Header
		Handle string
	}

	// OpenReq
	// Files are opened and created using the SSH_FXP_OPEN message
	OpenReq struct {
		Header
		Filename string
		Pflags   uint32
		Attrs    Attrs
	}

	ReadReq struct {
		Header
		Handle string
		Offset uint64
		Len    uint32
	}

	DataResp struct {
		Header
		Data []byte
	}

	Attrs struct {
		Size          uint64
		Uid           uint32
		Gid           uint32
		Permissions   FileMode
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
	case SSH_FXP_OPEN:
		m = &OpenReq{}
	case SSH_FXP_READ:
		m = &ReadReq{}
	case SSH_FXP_DATA:
		m = &DataResp{}
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
	case *OpenReq:
		return SSH_FXP_OPEN, nil
	case *ReadReq:
		return SSH_FXP_READ, nil
	default:
		return 0, fmt.Errorf("unhandled msg type: %T", m)
	}
}

func (h Header) id() uint32 {
	return h.Id
}

func (i *InitReq) UnmarshalBinary(b []byte) error {
	i.Version, b = Uint32(b)
	return nil
}
func (i *InitReq) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := binary.Write(buf, binary.BigEndian, i.Version); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (v *VersionResp) UnmarshalBinary(b []byte) error {
	v.Version, b = Uint32(b)
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
	r.Id, b = Uint32(b)
	r.Handle, b = String(b)
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
	if err := WriteUint32(buf, r.Id); err != nil {
		return nil, err
	}
	if err := WriteString(buf, r.Handle); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *StatusResp) UnmarshalBinary(b []byte) error {
	r.Id, b = Uint32(b)
	r.ErrorCode, b = Uint32(b)
	r.ErrorMessage, b = String(b)
	return nil
}
func (r *StatusResp) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (r *NameResp) UnmarshalBinary(b []byte) error {
	r.Id, b = Uint32(b)
	r.Count, b = Uint32(b)
	var flags uint32

	for i := uint32(0); i < r.Count; i++ {
		v := NameRespFile{}
		v.Filename, b = String(b)
		v.Longname, b = String(b)
		flags, b = Uint32(b)
		if flags&SSH_FILEXFER_ATTR_SIZE != 0 {
			v.Attrs.Size, b = Uint64(b)
		}
		if flags&SSH_FILEXFER_ATTR_UIDGID != 0 {
			v.Attrs.Uid, b = Uint32(b)
			v.Attrs.Gid, b = Uint32(b)
		}
		if flags&SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
			var p uint32
			p, b = Uint32(b)
			v.Attrs.Permissions = FileMode(p)
		}
		if flags&SSH_FILEXFER_ATTR_ACMODTIME != 0 {
			v.Attrs.Atime, b = Uint32(b)
			v.Attrs.Mtime, b = Uint32(b)
		}
		if flags&SSH_FILEXFER_ATTR_EXTENDED != 0 {
			v.Attrs.ExtendedCount, b = Uint32(b)
			if v.Attrs.ExtendedCount > 0 {
				panic("extended count not supported yet")
			}
		}

		r.Names = append(r.Names, v)
	}
	return nil
}

func (r *NameResp) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (r *OpenReq) UnmarshalBinary(b []byte) error {
	return nil
}
func (r *OpenReq) MarshalBinary() ([]byte, error) {
	if r.Pflags&SSH_FXF_READ == 0 {
		return nil, errors.New("SSH_FXF_READ needs to be set for reading")
	}
	buf := bytes.NewBuffer(nil)
	if err := WriteUint32(buf, r.Id); err != nil {
		return nil, err
	}
	if err := WriteString(buf, r.Filename); err != nil {
		return nil, err
	}
	if err := WriteUint32(buf, r.Pflags); err != nil {
		return nil, err
	}

	// currently write 0 flag mask and 0 attributes
	if err := WriteUint32(buf, 0); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (r *ReadReq) UnmarshalBinary(b []byte) error {
	return nil
}
func (r *ReadReq) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := WriteUint32(buf, r.Id); err != nil {
		return nil, err
	}
	if err := WriteString(buf, r.Handle); err != nil {
		return nil, err
	}
	if err := WriteUint64(buf, r.Offset); err != nil {
		return nil, err
	}
	if err := WriteUint32(buf, r.Len); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *DataResp) UnmarshalBinary(b []byte) error {
	r.Id, b = Uint32(b)
	_, b = Uint32(b)
	r.Data = b
	return nil
}
func (r *DataResp) MarshalBinary() ([]byte, error) {
	return nil, nil
}
