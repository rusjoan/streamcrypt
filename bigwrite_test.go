package streamcrypt

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// A single write larger than the sealing buffer (1MB) without WithImmutableSealing must produce
// a frame that opens to the original bytes, both when the argument has spare capacity and when it doesn't.
func TestBigWriteMutable(t *testing.T) {
	block, err := CipherBlockFromSecret([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{defaultMaxBufferSize, 4 << 20} {
		for _, spare := range []int{0, 64} { // 0: slices.Grow reallocates, 64: in-place shift
			want := make([]byte, size)
			rand.Read(want)
			p := make([]byte, size, size+spare)
			copy(p, want)

			enc, err := NewEncryptor(block)
			if err != nil {
				t.Fatal(err)
			}
			var frame bytes.Buffer
			n, err := enc.Seal(&frame).Write(p)
			if err != nil || n != size {
				t.Fatalf("size=%d spare=%d: write n=%d err=%v", size, spare, n, err)
			}
			if frame.Len() != size+enc.Overhead() {
				t.Fatalf("size=%d spare=%d: frame %d, want %d", size, spare, frame.Len(), size+enc.Overhead())
			}
			got, err := io.ReadAll(enc.Open(&frame))
			if err != nil {
				t.Fatalf("size=%d spare=%d: open: %v", size, spare, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("size=%d spare=%d: plaintext mismatch", size, spare)
			}
		}
	}
}
