package main

import (
	"debug/elf"
	"elfreader/options"
	"fmt"
	"os"
)

func main() {
	// format check
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <option> <file>\n", os.Args[0])
		os.Exit(1)
	}

	// option handle
	op := string(os.Args[1])

	// open ELF file
	f, err := elf.Open(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// option jump
	switch op {
	case "-A":
		options.AllInf(f, os.Args[2])
	case "-H":
		options.HeadInf(f, os.Args[2])
	case "-P":
		options.ProgramHeadInf(f, true)
	case "-S":
		{
			options.SectionHeadInf(f, true)
		}
	case "-Sym":
		{
			options.SymbolTableInf(f)
		}
	//TO DO: Note
	/*
		case "-N":
			options.NoteSectionInf(f)
	*/
	case "-R":
		{
			options.RelocsInf(f)
		}
		//TO DO: Version info
		/*
			case "-v":
				options.VersionInf(f)
		*/

	}
}
