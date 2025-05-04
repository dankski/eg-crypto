package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/dankski/shift"
)

func main() {
	crib := flag.String("crib", "", "crib to use for cracking")
	flag.Parse()

	if *crib == "" {
		fmt.Fprintln(os.Stderr, "Please provide a crib using the -crib flag")
		os.Exit(1)
	}

	ciphertext, err := io.ReadAll(os.Stdin)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading ciphertext:", err)
		os.Exit(1)
	}

	key, err := shift.Crack(ciphertext, []byte(*crib))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error cracking ciphertext:", err)
		os.Exit(1)
	}

	plaintext := shift.Decipher(ciphertext, byte(key))
	os.Stdout.Write(plaintext)
}
