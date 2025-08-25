package usftp

import (
	"path/filepath"
)

type (
	Visitor interface {
		Visit(file *NameRespFile) bool
		Files() []*NameRespFile
	}

	UnseenFileVisitor struct {
		exclude []string
		seen    map[string]*NameRespFile
		found   []*NameRespFile
	}
)

func NewUnseenFileVisitor(seen map[string]*NameRespFile, exclude []string) *UnseenFileVisitor {
	return &UnseenFileVisitor{seen: seen, exclude: exclude}
}
func (u *UnseenFileVisitor) Files() []*NameRespFile {
	return u.found
}

func (u *UnseenFileVisitor) Visit(file *NameRespFile) bool {
	fn := filepath.Join(file.Path, file.Filename)
	for _, v := range u.exclude {
		if fn == v {
			return false
		}
	}
	if _, ok := u.seen[fn]; ok {
		if u.seen[fn].Attrs.Size == file.Attrs.Size {
			return false
		}
	}
	u.found = append(u.found, file)
	return true
}
