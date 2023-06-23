package file

import (
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
)

// seekStart, seekCurrent, seekEnd are copies of
// io.SeekStart, io.SeekCurrent, and io.SeekEnd.
// We can't use the ones from package io because
// we want this code to build with Go 1.4 during
// cmd/dist bootstrap.
const (
	seekStart   int = 0
	seekCurrent int = 1
	seekEnd     int = 2
)

// A FileHeader represents an ELF file header.
type FileHeader struct {
	Class      elf.Class
	Data       elf.Data
	Version    elf.Version
	OSABI      elf.OSABI
	ABIVersion uint8
	ByteOrder  binary.ByteOrder
	Type       elf.Type
	Machine    elf.Machine
	Entry      uint64
}

// A File represents an open ELF file.
type File struct {
	FileHeader
	Sections []*Section
	Progs    []*Prog
	closer   io.Closer
	//gnuNeed   []elf.verneed
	gnuVersym []byte
}

// A ProgHeader represents a single ELF program header.
type ProgHeader struct {
	Type   elf.ProgType
	Flags  elf.ProgFlag
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

// A Prog represents a single ELF program header in an ELF binary.
type Prog struct {
	ProgHeader

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

// Open returns a new ReadSeeker reading the ELF program body.
func (p *Prog) Open() io.ReadSeeker { return io.NewSectionReader(p.sr, 0, 1<<63-1) }

// A Symbol represents an entry in an ELF symbol table section.
type Symbol struct {
	Name        string
	Info, Other byte
	Section     elf.SectionIndex
	Value, Size uint64

	// Version and Library are present only for the dynamic symbol
	// table.
	Version string
	Library string
}

// A SectionHeader represents a single ELF section header.
type SectionHeader struct {
	Name      string
	Type      elf.SectionType
	Flags     elf.SectionFlag
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64

	// FileSize is the size of this section in the file in bytes.
	// If a section is compressed, FileSize is the size of the
	// compressed data, while Size (above) is the size of the
	// uncompressed data.
	FileSize uint64
}

// A Section represents a single section in an ELF file.
type Section struct {
	SectionHeader

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	//
	// ReaderAt may be nil if the section is not easily available
	// in a random-access form. For example, a compressed section
	// may have a nil ReaderAt.
	io.ReaderAt
	sr *io.SectionReader

	compressionType   elf.CompressionType
	compressionOffset int64
}

// Data reads and returns the contents of the ELF section.
// Even if the section is stored compressed in the ELF file,
// Data returns uncompressed data.
func (s *Section) Data() []byte {
	dat := make([]byte, s.Size)
	n, _ := io.ReadFull(s.Open(), dat)
	return dat[0:n]
}

// Open returns a new ReadSeeker reading the ELF section.
// Even if the section is stored compressed in the ELF file,
// the ReadSeeker reads uncompressed data.
func (s *Section) Open() io.ReadSeeker {
	if s.Type == elf.SHT_NOBITS {
		return io.NewSectionReader(&zeroReader{}, 0, int64(s.Size))
	}
	if s.Flags&elf.SHF_COMPRESSED == 0 {
		return io.NewSectionReader(s.sr, 0, 1<<63-1)
	}
	if s.compressionType == elf.COMPRESS_ZLIB {
		return &readSeekerFromReader{
			reset: func() (io.Reader, error) {
				fr := io.NewSectionReader(s.sr, s.compressionOffset, int64(s.FileSize)-s.compressionOffset)
				return zlib.NewReader(fr)
			},
			size: int64(s.Size),
		}
	}
	return nil
}

// stringTable reads and returns the string table given by the
// specified link value.
func (f *File) stringTable(link uint32) []byte {
	if link <= 0 || link >= uint32(len(f.Sections)) {
		return nil
	}
	return f.Sections[link].Data()
}

// Open opens the named file using os.Open and prepares it for use as an ELF binary.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff := NewFile(f)

	ff.closer = f
	return ff, nil
}

// Close closes the File.
// If the File was created using NewFile directly instead of Open,
// Close has no effect.
func (f *File) Close() error {
	var err error
	if f.closer != nil {
		err = f.closer.Close()
		f.closer = nil
	}
	return err
}

func NewFile(r io.ReaderAt) *File {
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	// Read and decode ELF identifier
	var ident [16]uint8
	if _, err := r.ReadAt(ident[0:], 0); err != nil {
		return nil
	}
	if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
		return nil
	}

	f := new(File)
	f.Class = elf.Class(ident[elf.EI_CLASS])
	switch f.Class {
	case elf.ELFCLASS32:
	case elf.ELFCLASS64:
		// ok
	default:
		return nil
	}

	f.Data = elf.Data(ident[elf.EI_DATA])
	switch f.Data {
	case elf.ELFDATA2LSB:
		f.ByteOrder = binary.LittleEndian
	case elf.ELFDATA2MSB:
		f.ByteOrder = binary.BigEndian
	default:
		return nil
	}

	f.Version = elf.Version(ident[elf.EI_VERSION])
	if f.Version != elf.EV_CURRENT {
		return nil
	}

	f.OSABI = elf.OSABI(ident[elf.EI_OSABI])
	f.ABIVersion = ident[elf.EI_ABIVERSION]

	// Read ELF file header
	var phoff int64
	var phentsize, phnum int
	var shoff int64
	var shentsize, shnum, shstrndx int
	switch f.Class {
	case elf.ELFCLASS32:
		hdr := new(elf.Header32)
		sr.Seek(0, seekStart)
		if err := binary.Read(sr, f.ByteOrder, hdr); err != nil {
			return nil
		}
		f.Type = elf.Type(hdr.Type)
		f.Machine = elf.Machine(hdr.Machine)
		f.Entry = uint64(hdr.Entry)
		if v := elf.Version(hdr.Version); v != f.Version {
			return nil
		}
		phoff = int64(hdr.Phoff)
		phentsize = int(hdr.Phentsize)
		phnum = int(hdr.Phnum)
		shoff = int64(hdr.Shoff)
		shentsize = int(hdr.Shentsize)
		shnum = int(hdr.Shnum)
		shstrndx = int(hdr.Shstrndx)
	case elf.ELFCLASS64:
		hdr := new(elf.Header64)
		sr.Seek(0, seekStart)
		if err := binary.Read(sr, f.ByteOrder, hdr); err != nil {
			return nil
		}
		f.Type = elf.Type(hdr.Type)
		f.Machine = elf.Machine(hdr.Machine)
		f.Entry = hdr.Entry
		if v := elf.Version(hdr.Version); v != f.Version {
			return nil
		}
		phoff = int64(hdr.Phoff)
		phentsize = int(hdr.Phentsize)
		phnum = int(hdr.Phnum)
		shoff = int64(hdr.Shoff)
		shentsize = int(hdr.Shentsize)
		shnum = int(hdr.Shnum)
		shstrndx = int(hdr.Shstrndx)
	}

	if shoff < 0 {
		return nil
	}
	if phoff < 0 {
		return nil
	}

	if shoff == 0 && shnum != 0 {
		return nil
	}

	if shnum > 0 && shstrndx >= shnum {
		return nil
	}

	var wantPhentsize, wantShentsize int
	switch f.Class {
	case elf.ELFCLASS32:
		wantPhentsize = 8 * 4
		wantShentsize = 10 * 4
	case elf.ELFCLASS64:
		wantPhentsize = 2*4 + 6*8
		wantShentsize = 4*4 + 6*8
	}
	if phnum > 0 && phentsize < wantPhentsize {
		return nil
	}

	// Read program headers
	f.Progs = make([]*Prog, phnum)
	for i := 0; i < phnum; i++ {
		off := phoff + int64(i)*int64(phentsize)
		sr.Seek(off, seekStart)
		p := new(Prog)
		switch f.Class {
		case elf.ELFCLASS32:
			ph := new(elf.Prog32)
			if err := binary.Read(sr, f.ByteOrder, ph); err != nil {
				return nil
			}
			p.ProgHeader = ProgHeader{
				Type:   elf.ProgType(ph.Type),
				Flags:  elf.ProgFlag(ph.Flags),
				Off:    uint64(ph.Off),
				Vaddr:  uint64(ph.Vaddr),
				Paddr:  uint64(ph.Paddr),
				Filesz: uint64(ph.Filesz),
				Memsz:  uint64(ph.Memsz),
				Align:  uint64(ph.Align),
			}
		case elf.ELFCLASS64:
			ph := new(elf.Prog64)
			if err := binary.Read(sr, f.ByteOrder, ph); err != nil {
				return nil
			}
			p.ProgHeader = ProgHeader{
				Type:   elf.ProgType(ph.Type),
				Flags:  elf.ProgFlag(ph.Flags),
				Off:    ph.Off,
				Vaddr:  ph.Vaddr,
				Paddr:  ph.Paddr,
				Filesz: ph.Filesz,
				Memsz:  ph.Memsz,
				Align:  ph.Align,
			}
		}
		if int64(p.Off) < 0 {
			return nil
		}
		if int64(p.Filesz) < 0 {
			return nil
		}
		p.sr = io.NewSectionReader(r, int64(p.Off), int64(p.Filesz))
		p.ReaderAt = p.sr
		f.Progs[i] = p
	}

	// If the number of sections is greater than or equal to SHN_LORESERVE
	// (0xff00), shnum has the value zero and the actual number of section
	// header table entries is contained in the sh_size field of the section
	// header at index 0.
	if shoff > 0 && shnum == 0 {
		var typ, link uint32
		sr.Seek(shoff, seekStart)
		switch f.Class {
		case elf.ELFCLASS32:
			sh := new(elf.Section32)
			if err := binary.Read(sr, f.ByteOrder, sh); err != nil {
				return nil
			}
			shnum = int(sh.Size)
			typ = sh.Type
			link = sh.Link
		case elf.ELFCLASS64:
			sh := new(elf.Section64)
			if err := binary.Read(sr, f.ByteOrder, sh); err != nil {
				return nil
			}
			shnum = int(sh.Size)
			typ = sh.Type
			link = sh.Link
		}
		if elf.SectionType(typ) != elf.SHT_NULL {
			return nil
		}

		if shnum < int(elf.SHN_LORESERVE) {
			return nil
		}

		// If the section name string table section index is greater than or
		// equal to SHN_LORESERVE (0xff00), this member has the value
		// SHN_XINDEX (0xffff) and the actual index of the section name
		// string table section is contained in the sh_link field of the
		// section header at index 0.
		if shstrndx == int(elf.SHN_XINDEX) {
			shstrndx = int(link)
			if shstrndx < int(elf.SHN_LORESERVE) {
				return nil
			}
		}
	}

	if shnum > 0 && shentsize < wantShentsize {
		return nil
	}

	// Read section headers
	f.Sections = make([]*Section, 0, shnum)
	names := make([]uint32, 0, shnum)
	for i := 0; i < shnum; i++ {
		off := shoff + int64(i)*int64(shentsize)
		sr.Seek(off, seekStart)
		s := new(Section)
		switch f.Class {
		case elf.ELFCLASS32:
			sh := new(elf.Section32)
			if err := binary.Read(sr, f.ByteOrder, sh); err != nil {
				return nil
			}
			names = append(names, sh.Name)
			s.SectionHeader = SectionHeader{
				Type:      elf.SectionType(sh.Type),
				Flags:     elf.SectionFlag(sh.Flags),
				Addr:      uint64(sh.Addr),
				Offset:    uint64(sh.Off),
				FileSize:  uint64(sh.Size),
				Link:      sh.Link,
				Info:      sh.Info,
				Addralign: uint64(sh.Addralign),
				Entsize:   uint64(sh.Entsize),
			}
		case elf.ELFCLASS64:
			sh := new(elf.Section64)
			if err := binary.Read(sr, f.ByteOrder, sh); err != nil {
				return nil
			}
			names = append(names, sh.Name)
			s.SectionHeader = SectionHeader{
				Type:      elf.SectionType(sh.Type),
				Flags:     elf.SectionFlag(sh.Flags),
				Offset:    sh.Off,
				FileSize:  sh.Size,
				Addr:      sh.Addr,
				Link:      sh.Link,
				Info:      sh.Info,
				Addralign: sh.Addralign,
				Entsize:   sh.Entsize,
			}
		}
		if int64(s.Offset) < 0 {
			return nil
		}
		if int64(s.FileSize) < 0 {
			return nil
		}
		s.sr = io.NewSectionReader(r, int64(s.Offset), int64(s.FileSize))

		if s.Flags&elf.SHF_COMPRESSED == 0 {
			s.ReaderAt = s.sr
			s.Size = s.FileSize
		} else {
			// Read the compression header.
			switch f.Class {
			case elf.ELFCLASS32:
				ch := new(elf.Chdr32)
				if err := binary.Read(s.sr, f.ByteOrder, ch); err != nil {
					return nil
				}
				s.compressionType = elf.CompressionType(ch.Type)
				s.Size = uint64(ch.Size)
				s.Addralign = uint64(ch.Addralign)
				s.compressionOffset = int64(binary.Size(ch))
			case elf.ELFCLASS64:
				ch := new(elf.Chdr64)
				if err := binary.Read(s.sr, f.ByteOrder, ch); err != nil {
					return nil
				}
				s.compressionType = elf.CompressionType(ch.Type)
				s.Size = ch.Size
				s.Addralign = ch.Addralign
				s.compressionOffset = int64(binary.Size(ch))
			}
		}

		f.Sections = append(f.Sections, s)
	}

	if len(f.Sections) == 0 {
		return f
	}

	// Load section header string table.
	if shstrndx == 0 {
		// If the file has no section name string table,
		// shstrndx holds the value SHN_UNDEF (0).
		return f
	}
	shstr := f.Sections[shstrndx]
	if shstr.Type != elf.SHT_STRTAB {
		return nil
	}
	shstrtab := shstr.Data()

	for i, s := range f.Sections {
		var ok bool
		s.Name, ok = getString(shstrtab, int(names[i]))
		if !ok {
			return nil
		}
	}

	return f
}
