package main

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rusjoan/streamcrypt"
)

var secret = []byte("test-secret")

func writeFile() error {
	// open file (destination data container)
	file, err := os.OpenFile(filepath.Join(os.TempDir(), "streamcrypt.bin"), os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	// init encryptor (sealer)
	secretBlock, err := streamcrypt.CipherBlockFromSecret(secret)
	if err != nil {
		return err
	}

	enc, err := streamcrypt.NewEncryptor(secretBlock)
	if err != nil {
		return err
	}

	// write encrypted compressed json-data
	w := gzip.NewWriter(enc.Seal(file))
	defer w.Close()

	for _, datum := range []string{"foo", "bar", "baz"} {
		if err = json.NewEncoder(w).Encode(datum); err != nil {
			return err
		}
	}

	return nil
}

func readFile() error {
	// open file (destination data container)
	file, err := os.OpenFile(filepath.Join(os.TempDir(), "streamcrypt.bin"), os.O_RDONLY, 0600)
	if err != nil {
		return err
	}

	// init encryptor (opener)
	secretBlock, err := streamcrypt.CipherBlockFromSecret(secret)
	if err != nil {
		return err
	}

	enc, err := streamcrypt.NewEncryptor(secretBlock)
	if err != nil {
		return err
	}

	// read encrypted compressed json-data
	r, err := gzip.NewReader(enc.Open(file))
	if err != nil {
		return err
	}
	defer r.Close()

	var decoder = json.NewDecoder(r)
	var data string

	for err = decoder.Decode(&data); err == nil; err = decoder.Decode(&data) {
		fmt.Println(data)
	}

	return err
}

func main() {
	if err := writeFile(); err != nil {
		panic(err)
	}
	if err := readFile(); err != nil && !errors.Is(err, io.EOF) {
		panic(err)
	}
}
