package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	byteDestination := make([]byte, 32)

	_, err := rand.Read(byteDestination)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generating key:", err)
		os.Exit(1)
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(byteDestination))
}
