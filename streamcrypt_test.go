package streamcrypt

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"slices"
	"testing"
)

var (
	secretBlock, _ = CipherBlockFromSecret([]byte("test-secret"))
	testSizes      = []int{1 << 14, 1 << 20, 1 << 25, 1 << 30} // 16KB, 1MB, 32MB, 1GB
	benchSizes     = []int{1 << 10, 1 << 20, 1 << 25}
)

func TestPlaintext(t *testing.T) {
	var testData = []byte("hello world")

	enc, err := NewEncryptor(secretBlock)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer

	// Write encrypted data
	w := enc.Seal(&buf)
	if _, err = w.Write(testData); err != nil {
		t.Fatal(err)
	}

	// Decrypt and read
	r := enc.Open(&buf)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(testData, out) {
		t.Errorf("expected %q, got %q", testData, out)
	}
}

func TestGzipStream(t *testing.T) {
	var testData = []byte("hello world")

	enc, err := NewEncryptor(secretBlock)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer

	// Write encrypted compressed data
	w := gzip.NewWriter(enc.Seal(&buf))

	if _, err = w.Write(testData); err != nil {
		t.Fatal(err)
	}

	if err = w.Close(); err != nil {
		t.Fatal(err)
	}

	// Decrypt, gunzip and read
	r, err := gzip.NewReader(enc.Open(&buf))
	if err != nil {
		t.Fatal(err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if err = r.Close(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(testData, out) {
		t.Errorf("expected %q, got %q", testData, out)
	}
}

func TestJsonGzipStream(t *testing.T) {
	type someData struct {
		Foo string `json:"foo"`
		Bar int    `json:"bar"`
		Baz string `json:"baz"`
	}

	var testData = []someData{
		{Foo: "foo1", Bar: 1, Baz: "baz1"},
		{Foo: "foo2", Bar: 2, Baz: "baz2"},
		{Foo: "foo3", Bar: 3, Baz: "baz3"},
	}

	enc, err := NewEncryptor(secretBlock)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer

	// Write encrypted compressed json-data
	w := gzip.NewWriter(enc.Seal(&buf))
	for _, datum := range testData {
		if err = json.NewEncoder(w).Encode(datum); err != nil {
			t.Fatal(err)
		}
	}

	if err = w.Close(); err != nil {
		t.Fatal(err)
	}

	// Decrypt, gunzip, and decode json
	r, err := gzip.NewReader(enc.Open(&buf))
	if err != nil {
		t.Fatal(err)
	}

	var decoder = json.NewDecoder(r)
	var assertData = []someData(nil)
	var data someData

	for err = decoder.Decode(&data); err == nil; err = decoder.Decode(&data) {
		assertData = append(assertData, data)
	}

	if err = r.Close(); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(testData, assertData) {
		t.Errorf("expected %q, got %q", testData, assertData)
	}
}

func BenchmarkTee(b *testing.B) {
	key := []byte("secret")
	block, _ := CipherBlockFromSecret(key)
	enc, _ := NewEncryptor(block)

	var buf = make([]byte, 1024)
	var r = io.TeeReader(rand.Reader, enc.Seal(io.Discard))

	b.Run(fmt.Sprintf("rnd->encryptor->discard"), func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r.Read(buf)
		}
	})
}

func BenchmarkEncryption(b *testing.B) {
	for _, size := range benchSizes {
		data := genData(size)
		enc, _ := NewEncryptor(secretBlock)

		b.Run("Size_"+humanizeBytes(size), func(b *testing.B) {
			b.Run("Encrypt", func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()

				w := enc.Seal(io.Discard)
				for i := 0; i < b.N; i++ {
					w.Write(data)
				}
			})

			b.Run("Encrypt+Decrypt", func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()

				var buf bytes.Buffer
				enc.Seal(&buf).Write(data)
				encrypted := buf.Bytes()

				r := enc.Open(bytes.NewReader(encrypted))
				for i := 0; i < b.N; i++ {
					io.Copy(io.Discard, r)
				}
			})
		})
	}
}

func TestMemoryOverhead(t *testing.T) {
	debug.SetGCPercent(-1)    // disable automatic GC
	const maxHeapDelta = 1024 // 1KB

	enc, _ := NewEncryptor(secretBlock)
	var readBuf = make([]byte, 512)
	//enc = enc.WithSealingBufferSize(1); var readBuf = make([]byte, 1024, 1024+enc.Overhead()) // memory delta=0

	for _, size := range testSizes {
		runtime.GC() // collect garbage

		// imitate some work by encrypting random bytes to io.Discard sinkhole
		sealer := enc.Seal(io.Discard)
		r := io.TeeReader(io.LimitReader(rand.Reader, int64(size)), sealer)

		start := heapSize() // heap size at start
		for _, err := r.Read(readBuf); err == nil; _, err = r.Read(readBuf) {
			continue
		}
		delta := heapSize() - start // heap size at finish

		t.Logf("Size: %s, Memory delta: %s",
			humanizeBytes(size),
			humanizeBytes(int(delta)),
		)

		if delta > maxHeapDelta { // ensure constant memory consumption
			t.Errorf("Memory scaling violation: input %s → memory %s",
				humanizeBytes(size),
				humanizeBytes(int(delta)))
		}
	}
}

func heapSize() uint64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return memStats.HeapAlloc
}

func humanizeBytes(b int) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func genData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}
