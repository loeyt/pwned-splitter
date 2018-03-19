package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"
)

const usage = `%[1]s splits a Pwned Passwords list file in to smaller files.
This might be useful for k-anonymous access.
This tool expects hash-ordered input.

Usage:
  %[1]s [options] [<file>]

Options:
`

var errNoMatch = fmt.Errorf("no match found")

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	pathFormat := fs.String("path", path.Join("%%", "%%%"), "path to store, with '%' as the wildcard")
	hashSize := fs.Uint("hash-size", 63, "line length of the input")
	bufferSize := fs.Uint("buffer-size", 1024, "number of hashes to read at once")
	progress := fs.Bool("progress", false, "show progress")
	stripPrefix := fs.Bool("strip-prefix", true, "strip the prefix from each line")
	fs.Parse(os.Args[1:])

	var input io.Reader
	args := fs.Args()
	switch len(args) {
	case 0:
		input = os.Stdin
	case 1:
		var err error
		input, err = os.Open(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open file: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		fs.PrintDefaults()
		os.Exit(2)
	}

	prefixLength := strings.Count(*pathFormat, "%")
	// format := strings.Replace(*pathFormat, "%", "%c", -1)

	buf := make([]byte, *hashSize**bufferSize)
	n, err := io.ReadFull(input, buf)
	if err == io.ErrUnexpectedEOF {
		buf = buf[:n]
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read: %v\n", err)
		os.Exit(1)
	}
	for len(buf) > 0 {
		if len(buf)%int(*hashSize) != 0 {
			fmt.Fprintf(os.Stderr, "buffer not divisible by %d\n", *hashSize)
		}
		if *progress {
			fmt.Print("\r", string(buf[:prefixLength]))
		}
		i := sort.Search(len(buf)/int(*hashSize), func(i int) bool {
			return bytes.Compare(buf[i*int(*hashSize):i*int(*hashSize)+prefixLength], buf[0:prefixLength]) != 0
		})
		if i == int(*bufferSize) {
			if *progress {
				fmt.Println()
			}
			fmt.Fprintf(os.Stderr, "buffer too small\n")
			os.Exit(1)
		}
		filename := prefixPath(buf[:prefixLength], *pathFormat)
		fileLength := i * int(*hashSize)
		if *stripPrefix {
			for n := 0; n < i; n++ {
				copy(buf[n*(int(*hashSize)-prefixLength):], buf[n*int(*hashSize)+prefixLength:(n+1)*int(*hashSize)])
			}
			fileLength -= i * prefixLength
		}
		err = ioutil.WriteFile(filename, buf[:fileLength], 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to write file %s: %v\n", filename, err)
			os.Exit(1)
		}
		copy(buf, buf[i*int(*hashSize):])
		n, err = io.ReadFull(input, buf[len(buf)-i*int(*hashSize):])
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			buf = buf[:len(buf)-i*int(*hashSize)+n]
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read: %v\n", err)
			os.Exit(1)
		}
	}
	if *progress {
		fmt.Println()
	}
}

func prefixPath(prefix []byte, format string) string {
	rv := []byte(format)
	for n := 0; n < len(prefix); n++ {
		rv[bytes.IndexByte(rv, '%')] = prefix[n]
	}
	return string(rv)
}
