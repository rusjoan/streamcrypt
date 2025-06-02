# streamcrypt [![Go Reference](https://pkg.go.dev/badge/github.com/rusjoan/streamcrypt.svg)](https://pkg.go.dev/github.com/rusjoan/streamcrypt)

Seamless encryption layer for Go data streams. Wrap any `io.Reader`/`io.Writer` with authenticated encryption (AES-GCM) while preserving streaming capabilities.

## Why streamcrypt?

- 🔥 **Append-safe** — add new data without corrupting existing stream
- 🔥 **Constant memory** — up to 0 allocations; handles TBs with KBs of RAM
- 🔥 **Compression-friendly** — works with gzip/zstd/etc
- ✅ **Drop-in encryption** for existing pipelines
- ✅ **Zero dependencies** — pure Go standard library
- ✅ **Low overhead** — +32 bytes per chunk (~13% for JSON+GZIP)
- ✅ **Bidirectional** — same key for read/write

## Installation

```bash
go get github.com/rusjoan/streamcrypt
```

## Quick start

### Basic usage
```go
package main

import (
	"bytes"
	"github.com/rusjoan/streamcrypt"
)

func main() {
	// 1. Initialize with your secret
	var key = []byte("secret")
	var secretBlock, _ = streamcrypt.CipherBlockFromSecret(key)
	var enc, _ = streamcrypt.NewEncryptor(secretBlock)

	// 2. Encrypt to buffer
	var buf bytes.Buffer
	w := enc.Seal(&buf)
	w.Write([]byte("sensitive data"))

	// 3. Decrypt back
	r := enc.Open(&buf)
	data, _ := io.ReadAll(r) // "sensitive data"

	fmt.Println(string(data))
}
```

### Real-world Example (GZIP + JSON)

```go
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
```

### Fine-tuning

#### Limit internal buffer size
```go
var maxBufferSize = 2048 // limits buffer's grow up to 2048 bytes
var enc, _ = NewEncryptor(secretBlock)
enc = enc.WithSealingBufferSize(maxBufferSize) // default=1MB

sealer := enc.Seal(io.Discard)
sealer.Write(data)
// if len(data) < maxBufferSize-enc.Overhead():
//  - heap grows up to maxBufferSize
//  - data has NO MUTATIONS
// otherwise:
//  - heap grows
//  - data is MUTATED
```

#### Ensure sealer immutability
```go
// this options forbids sealer to mutate writer's argument
var enc, _ = NewEncryptor(secretBlock)
enc = enc.WithImmutableSealing()

sealer := enc.Seal(io.Discard)
sealer.Write(data) // heap grows, +1 allocation, data has NO MUTATIONS
```

#### Ultimate Zero allocations, Zero heap grow
```go
// if you know, that your single write data size
// is no more than X bytes, then ensure than data slice has
// capacity >= X + enc.Overhead() bytes

// in this example we assume that our data chunks are up to 1GB (1<<30 bytes)
var enc, _ = NewEncryptor(secretBlock)
var data = make([]byte, 1<<30, 1<<30+enc.Overhead()) // len=1GB, cap=1GB+overhead

// use of enc.Overhead() gives enough capacity for in-place data processing without further allocations

sealer := enc.Seal(io.Discard)
sealer.Write(data) // heap grow=0, allocs=0, data is MUTATED
```

## How It Works

### Encryption Scheme

```
[4-byte chunk size][encrypted data][4-byte size][data]...
```

1. Each chunk is encrypted with AES-GCM (random nonce)
2. Chunk size precedes the encrypted payload (uint32 BE)
3. **Storage overhead**: ~13% on gzip stream (28 bytes per chunk: GCM tag + nonce + length prefix)

### Why Accept This Overhead?

While +32 bytes/chunk storage overhead exists, this design enables:
* Memory efficiency — Processes TBs of data with KBs of RAM
* Pipeline flexibility — Works between compression stages
* Hassle-free data append — add any data at any time to existing stream
* Random access — Skip to any chunk without full decryption

### Performance

```
// allocs
goos: darwin
goarch: arm64
pkg: github.com/rusjoan/streamcrypt
cpu: Apple M1 Pro
    BenchmarkTee
    BenchmarkTee/rnd->encryptor->discard
    BenchmarkTee/rnd->encryptor->discard-10     765747      1525 ns/op      0 B/op      0 allocs/op
PASS

// heap overhead
=== RUN   TestMemoryOverhead
    streamcrypt_test.go:218: Size: 16.0 KiB, Memory delta: 704 B
    streamcrypt_test.go:218: Size: 1.0 MiB, Memory delta: 576 B
    streamcrypt_test.go:218: Size: 32.0 MiB, Memory delta: 576 B
    streamcrypt_test.go:218: Size: 1.0 GiB, Memory delta: 576 B
--- PASS: TestMemoryOverhead (2.42s)
PASS
```

## Examples

### See working implementations in:

* /example/main.go - JSON-encoder + GZIP + encrypt read/write demo

## Security Notes

* 🔐 Uses standard Go crypto implementations (AES-GCM)
* ⚠️ Important: Rotate keys periodically
* 🔄 Each chunk gets unique nonce

## Contributing

PRs and stars welcome! Please:

* Discuss major changes in issues
* Keep API backward compatible
* Add tests for new features

## License

MIT Copyright © 2025 Evgeny Murashkin
