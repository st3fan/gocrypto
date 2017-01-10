package pkcs7

import (
	"crypto/sha256"
	"io"
)

type Hashable interface {
	Hash() ([]byte, error)
}

type hashableReader struct {
	r io.Reader
}

func (h *hashableReader) Hash() ([]byte, error) {
	hash := sha256.New()

	if _, err := io.Copy(hash, h.r); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// Creates a new Hashable from io.Reader
func NewHashableReader(r io.Reader) Hashable {
	return &hashableReader{r: r}
}

type hashableBytes struct {
	b []byte
}

func (h *hashableBytes) Hash() ([]byte, error) {
	hash := sha256.New()
	hash.Write(h.b)
	return hash.Sum(nil), nil
}

// Creates a new Hashable from bytes
func NewHashableBytes(b []byte) Hashable {
	return &hashableBytes{b: b}
}
