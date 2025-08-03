package usftp

// FileMode is a partial implementation of FileMode as the std lib implementation is not
// compatible for reasons I am yet to fully understand
type FileMode uint32

const (
	ModeType    = 0xF000
	ModeDir     = 0x4000
	ModeRegular = 0x8000
)

func (m FileMode) String() string {
	b := make([]byte, 10)
	switch m & ModeType {
	case ModeDir:
		b[0] = 'd'
	case ModeRegular:
		b[0] = '-'
	}

	const rwx = "rwxrwxrwx"
	for i, c := range rwx {
		if m&(1<<uint(9-1-i)) != 0 {
			b[i+1] = byte(c)
		} else {
			b[i+1] = '-'
		}
	}
	return string(b)
}

func (m FileMode) IsDir() bool {
	return (m & ModeType) == ModeDir
}

func (m FileMode) IsRegular() bool {
	return (m & ModeType) == ModeRegular
}
