package streamcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"slices"
)

const prefixSize = 4 // 4 bytes for uint32 prefix

// Buffers up to 1MB are preserved in memory, avoiding GC overhead for common cases
const defaultMaxBufferSize = 1 << 20

type Encryptor struct {
	enc cipher.AEAD

	// read
	upstream io.Reader
	rbuf     []byte
	index    int

	// write
	downstream io.Writer
	wbuf       []byte
	wbufmax    int
	immutable  bool
}

func CipherBlockFromSecret(secret []byte) (cipher.Block, error) {
	hash := sha256.Sum256(secret)
	return aes.NewCipher(hash[:])
}

func NewEncryptor(cipherBlock cipher.Block) (*Encryptor, error) {
	enc, err := cipher.NewGCMWithRandomNonce(cipherBlock)
	if err != nil {
		return nil, err
	}

	return &Encryptor{
		enc:     enc,
		wbufmax: defaultMaxBufferSize,
	}, nil
}

// WithImmutableSealing guarantees that data passed to Sealer won't be modified
func (e *Encryptor) WithImmutableSealing() *Encryptor {
	e.immutable = true
	return e
}

// WithSealingBufferSize allows internal sealing buffer to grow up to specified size to reuse between writes
func (e *Encryptor) WithSealingBufferSize(size int) *Encryptor {
	e.wbufmax = size
	return e
}

// Seal encrypts given data and writes to downstream
func (e *Encryptor) Seal(w io.Writer) io.Writer {
	e.downstream = w
	e.wbuf = make([]byte, 0, 16)
	return e
}

func (e *Encryptor) Write(p []byte) (n int, err error) {
	// plaintext, ciphertext and full length
	var plen, clen, tlen = len(p), len(p) + e.enc.Overhead(), len(p) + e.Overhead()
	var buf []byte

	// don't use internal buffer (allow allocations) if argument full length > max buf size
	if tlen > e.wbufmax {
		if e.immutable {
			buf = make([]byte, tlen)
		} else {
			buf = slices.Grow(p[:0], tlen)[:tlen] // grow argument's capacity to ensure it has enough space
			copy(buf[prefixSize:], p[:plen])      // shift data, preserving space for prefix
			p = p[prefixSize:]                    // update argument to use shifted space
		}
	} else {
		if cap(e.wbuf) < tlen {
			e.wbuf = slices.Grow(e.wbuf[:0], tlen)
		}
		buf = e.wbuf[:tlen]
	}

	// seal using prepared buffer, leaving some space for prefix
	e.enc.Seal(buf[prefixSize:][:0], nil, p, nil)

	// put ciphertext length prefix
	binary.BigEndian.PutUint32(buf[:prefixSize], uint32(clen))

	// write sealed data with prefix
	if _, err = e.downstream.Write(buf[:tlen]); err != nil {
		return 0, err
	}

	// return original length
	return plen, nil
}

// Open decrypts data from given reader; it may retain some trailing data in internal buffer between reads
func (e *Encryptor) Open(r io.Reader) io.Reader {
	e.rbuf = nil
	e.upstream = r
	return e
}

func (e *Encryptor) Read(p []byte) (n int, err error) {
	// return trailing data that remains in buffer
	if e.index < len(e.rbuf) {
		n = copy(p, e.rbuf[e.index:])
		e.index += n
		return n, nil
	}

	// read chunk length
	var length uint32
	err = binary.Read(e.upstream, binary.BigEndian, &length)
	if err != nil {
		return 0, err // including io.EOF
	}

	// read exact chunk length data
	e.rbuf = make([]byte, length)
	if _, err = io.ReadFull(e.upstream, e.rbuf); err != nil {
		return 0, err
	}

	// decrypt data using the same data buffer
	e.rbuf, err = e.enc.Open(e.rbuf[:0], nil, e.rbuf, nil)
	if err != nil {
		return 0, err
	}

	// reset buffer cursor
	e.index = 0

	// copy (output) up to len(p) bytes
	n = copy(p, e.rbuf)
	e.index = n
	return n, nil
}

// Overhead returns sealing overhead: nonce+tag+uint32
func (e *Encryptor) Overhead() int {
	return e.enc.Overhead() + prefixSize
}
