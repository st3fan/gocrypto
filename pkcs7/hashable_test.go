package pkcs7

import (
	"bytes"
	"os"
	"testing"
)

func Test_NewHashableReader(t *testing.T) {
	cases := []struct {
		FileName string
		Hash     []byte
		Error    string
	}{
		{
			FileName: "testdata/test1.txt",
			Hash: []byte{
				112, 80, 230, 94, 235, 41, 94, 59,
				18, 172, 134, 98, 53, 154, 178, 111,
				36, 89, 195, 198, 55, 200, 95, 36,
				193, 157, 229, 137, 123, 224, 99, 221,
			},
			Error: "",
		},
	}

	for _, c := range cases {
		f, err := os.Open(c.FileName)
		if err != nil {
			t.Errorf("%v", err.Error())
			continue
		}
		defer f.Close()

		hashable := NewHashableReader(f)
		if hashable == nil {
			t.Errorf("Got nil from NewHashableReader(\"%v\")")
			continue
		}

		hash, err := hashable.Hash()
		if c.Error != "" {
			if err != nil && err.Error() == c.Error {
				continue
			}

			t.Errorf("Expected Error %v, found %v", c.Error, err)
			continue
		}

		if l := len(hash); l != 32 {
			t.Errorf("len(hash) must be 32, found %v", l)
			continue
		}

		if !bytes.Equal(hash, c.Hash) {
			t.Errorf("Expected hash %v for file %v, found %v", c.Hash, c.FileName, hash)
		}
	}
}

func Test_NewHashableBytes(t *testing.T) {
	cases := []struct {
		Data  []byte
		Hash  []byte
		Error string
	}{
		{
			Data: []byte("Hello World!"),
			Hash: []byte{
				127, 131, 177, 101, 127, 241, 252, 83, 185, 45,
				193, 129, 72, 161, 214, 93, 252, 45, 75, 31, 163,
				214, 119, 40, 74, 221, 210, 0, 18, 109, 144, 105,
			},
			Error: "",
		},
	}

	for i, c := range cases {
		hashable := NewHashableBytes(c.Data)
		if hashable == nil {
			t.Errorf("Got nil from NewHashableReader(\"%v\")")
			continue
		}

		hash, err := hashable.Hash()
		if c.Error != "" {
			if err != nil && err.Error() == c.Error {
				continue
			}

			t.Errorf("Expected Error %v, found %v", c.Error, err)
			continue
		}

		if l := len(hash); l != 32 {
			t.Errorf("len(hash) must be 32, found %v", l)
			continue
		}

		if !bytes.Equal(hash, c.Hash) {
			t.Errorf("Expected hash %v for test %v, found %v", c.Hash, i, hash)
		}
	}
}
