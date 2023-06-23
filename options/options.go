package options

import (
	"debug/elf"
	"fmt"
	"log"
	"os"
	"text/tabwriter"
)

type Note struct {
	Name string
	Type uint32
	Desc []byte
}

func HeadInf(f *elf.File, fName string) {
	fmt.Println("ELF Header:")

	// get Magic Number
	r, _ := os.Open(fName)
	var ident [16]uint8
	if _, err := r.ReadAt(ident[0:], 0); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Magic:	%x\n", ident)

	// Others
	fmt.Printf("  Class:	%v\n", f.FileHeader.Class)
	fmt.Printf("  Data:		%v\n", f.FileHeader.Data)
	fmt.Printf("  Version:	%v\n", f.FileHeader.Version)
	fmt.Printf("  OSABI:	%v\n", f.FileHeader.OSABI)
	fmt.Printf("  ABIVersion:	%d\n", f.FileHeader.ABIVersion)
	fmt.Printf("  ByteOrder:	%v\n", f.FileHeader.ByteOrder)
	fmt.Printf("  Type:		%v\n", f.FileHeader.Type)
	fmt.Printf("  Machine:	%v\n", f.FileHeader.Machine)
	fmt.Printf("  Entry:	%d\n", f.FileHeader.Entry)
}

func ProgramHeadInf(f *elf.File, all bool) {
	// AllInf Specialized
	if all {
		fmt.Printf("ELF file type is %v\n", f.FileHeader.Type)
		fmt.Printf("Entry point %d\n", f.FileHeader.Entry)
		fmt.Printf("0x%d\n", len(f.Progs))
		fmt.Println()
	}

	fmt.Println("Program Headers:")
	// set tabwriter width 8
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 8, ' ', tabwriter.TabIndent)
	fmt.Fprintln(w, "Type:\tFlags:\tOffset:\tvAddr:\tpAddr:\tfSize:\tmSize:\tAlignment:")
	for _, phdr := range f.Progs {
		fmt.Fprintf(w, "%v\t", phdr.Type)
		fmt.Fprintf(w, "%v\t", phdr.Flags)
		fmt.Fprintf(w, "0x%x\t", phdr.Off)
		fmt.Fprintf(w, "0x%x\t", phdr.Vaddr)
		fmt.Fprintf(w, "0x%x\t", phdr.Paddr)
		fmt.Fprintf(w, "%v\t", phdr.Filesz)
		fmt.Fprintf(w, "%v\t", phdr.Memsz)
		fmt.Fprintf(w, "%v\t\n", phdr.Align)
	}
	// refresh Write
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Mapping:")
	for _, sect := range f.Sections {
		for _, phdr := range f.Progs {
			if sect.Flags&elf.SHF_ALLOC != 0 && sect.Addr >= phdr.Vaddr && sect.Addr+sect.Size <= phdr.Vaddr+phdr.Memsz {
				fmt.Printf("%v -> %v  ", sect.Name, phdr.Type)
			}
		}
	}
	fmt.Println()
}

func SectionHeadInf(f *elf.File, all bool) {
	// AllInf Specialized
	if all {
		fmt.Printf("ELF file type is %v\n", f.FileHeader.Type)
		fmt.Printf("Entry point %d\n", f.FileHeader.Entry)
		fmt.Printf("0x%d\n", len(f.Sections))
		fmt.Println()
	}

	fmt.Println("Section Headers:")
	// set tabwriter width 8
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 8, ' ', tabwriter.TabIndent)
	fmt.Fprintln(w, "Name:\tType:\tFlags:\tAddr:\tOffset:\tSize:\tLink:\tInfo:\tAlign:\tEntSize:")
	for _, shdr := range f.Sections {
		if shdr.Name == "" {
			fmt.Fprintf(w, "Nil\t")
		} else {
			fmt.Fprintf(w, "%v\t", shdr.Name)
		}
		fmt.Fprintf(w, "%v\t", shdr.Type)
		fmt.Fprintf(w, "%v\t", shdr.Flags)
		fmt.Fprintf(w, "0x%x\t", shdr.Addr)
		fmt.Fprintf(w, "0x%x\t", shdr.Offset)
		fmt.Fprintf(w, "%v\t", shdr.Size)
		fmt.Fprintf(w, "%v\t", shdr.Link)
		fmt.Fprintf(w, "%v\t", shdr.Info)
		fmt.Fprintf(w, "%v\t", shdr.Addralign)
		fmt.Fprintf(w, "%v\t\n", shdr.Entsize)
	}
	// refresh Write
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Mapping:")
	for _, sect := range f.Sections {
		for _, phdr := range f.Progs {
			if sect.Flags&elf.SHF_ALLOC != 0 && sect.Addr >= phdr.Vaddr && sect.Addr+sect.Size <= phdr.Vaddr+phdr.Memsz {
				fmt.Printf("%v -> %v  ", sect.Name, phdr.Type)
			}
		}
	}
	fmt.Println()
}

func SymbolTableInf(f *elf.File) {
	fmt.Println("Symbol Table:")
	// set tabwriter width 8
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 8, ' ', tabwriter.TabIndent)
	fmt.Fprintln(w, "Name:\tValue:\tSize:\tVersion:\tLib:\tNdx:")

	symtab, err := f.Symbols()
	if err != nil {
		log.Fatal(err)
	}

	for _, sym := range symtab {
		if sym.Name != "" {
			fmt.Fprintf(w, "%v\t", sym.Name)
			fmt.Fprintf(w, "0x%x\t", sym.Value)
			fmt.Fprintf(w, "%v\t", sym.Size)
			fmt.Fprintf(w, "%v\t", sym.Version)
			fmt.Fprintf(w, "%v\t", sym.Library)
			fmt.Fprintf(w, "%v\t\n", sym.Section)
		}
	}
	// refresh Write
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}
}

//TO DO:
//a useable Note reader
/*
func NoteSectionInf(f *elf.File) {
	for _, section := range f.Sections {
		if section.Type == elf.SHT_NOTE {
			fmt.Printf("Notes in section %s:\n", section.Name)

			data, err := section.Data()
			if err != nil {
				fmt.Printf("Error reading data from section %s: %v\n", section.Name, err)
				continue
			}

			for len(data) > 0 {
				var note Note

				// Parse name and type fields
				if len(data) < 8 {
					fmt.Println("Error: data slice too short")
					break
				}
				nameLen, typeVal := binary.LittleEndian.Uint32(data[0:4]), binary.LittleEndian.Uint32(data[4:8])
				note.Name, note.Type = string(data[8:8+nameLen]), typeVal

				// Parse desc field
				descLen := binary.LittleEndian.Uint32(data[8+nameLen : 8+nameLen+4])
				note.Desc = data[8+nameLen+4 : 8+nameLen+4+descLen]

				// Print note
				fmt.Printf("  Name: %s\n", note.Name)
				fmt.Printf("  Type: %d\n", note.Type)
				fmt.Printf("  Desc: %v\n", note.Desc)

				// Move to next note
				data = data[8+nameLen+4+descLen:]
			}
		}
	}
}
*/

func RelocsInf(f *elf.File) {
	fmt.Println("Relocation Sections:")
	// set tabwriter width 8
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 8, ' ', tabwriter.TabIndent)
	fmt.Fprintf(w, "Name:\tSize:\tOffset:\n")
	for _, section := range f.Sections {
		if section.Type == elf.SHT_REL || section.Type == elf.SHT_RELA {
			fmt.Fprintf(w, "%s\t", section.Name)
			fmt.Fprintf(w, "%d\t", section.Size)
			fmt.Fprintf(w, "%d\n", section.Offset)
		}
	}
	//refresh Write
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}
}

//TO DO:
//a usable Version info reader
/*
func VersionInf(f *elf.File) {
	section := f.Section(".gnu.version_r")
	if section == nil {
		fmt.Println("No version information found.")
		return
	}

	data, err := section.Data()
	if err != nil {
		fmt.Println("Error reading version information:", err)
		return
	}

	fmt.Printf("Version information (%d bytes):\n", len(data))

	// Parse the version information
	buf := bufio.NewReader(bytes.NewBuffer(data))
	for {
		// Read the version index
		index, err := readVarint(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("Error reading version index:", err)
			return
		}

		// Read the version name
		nameOffset, err := readVarint(buf)
		if err != nil {
			fmt.Println("Error reading version name offset:", err)
			return
		}
		name := "<unknown>"
		if nameOffset != 0 {
			nameSection := f.Section(".dynstr")
			if nameSection != nil {
				nameData, err := nameSection.Data()
				if err == nil {
					name = readCStringAtOffset(nameData, uint64(nameOffset))
				}
			}
		}

		// Read the version parent index
		parent, err := readVarint(buf)
		if err != nil {
			fmt.Println("Error reading version parent index:", err)
			return
		}

		fmt.Printf("Version %d: %s (parent %d)\n", index, name, parent)
	}
}

// readVarint reads a varint from r and returns it.
func readVarint(r *bufio.Reader) (int64, error) {
	var x int64
	var s uint
	for i := 0; i < 10; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		x |= int64(b&0x7f) << s
		if b&0x80 == 0 {
			return x, nil
		}
		s += 7
	}
	return 0, fmt.Errorf("varint too long")
}

// readCStringAtOffset reads a null-terminated C string from data at the given offset and returns the string.
func readCStringAtOffset(data []byte, offset uint64) string {
	end := bytes.IndexByte(data[offset:], 0)
	if end == -1 {
		return string(data[offset:])
	}
	return string(data[offset : offset+uint64(end)])
}
*/

func AllInf(f *elf.File, fName string) {
	HeadInf(f, fName)
	fmt.Println()
	ProgramHeadInf(f, false)
	fmt.Println()
	SectionHeadInf(f, false)
	fmt.Println()
	SymbolTableInf(f)
	fmt.Println()
	RelocsInf(f)
}
