package EncryptorWriter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

type V struct {
	buf      []byte
	wholeBuf []byte
	enc      cipher.BlockMode
	out      io.Writer
}

func appendData(buf []byte, data []byte) (newBuf []byte, remains []byte) {
	avail := cap(buf) - len(buf)

	if avail >= len(data) {
		newBuf = append(buf, data...)
		remains = nil
		return
	}

	newBuf = append(buf, data[:avail]...)
	remains = data[avail:]
	return
}

func pad(data []byte, blockSize int) ([]byte, error) {
	diff := blockSize - len(data)%blockSize
	data = append(data, make([]byte, diff)...)
	dataLen := len(data)

	for i := 0; i < diff; i++ {
		data[dataLen-1-i] = byte(diff)
	}

	return data, nil
}

func Create(pk rsa.PublicKey, out io.Writer) *V {
	rng := rand.Reader

	r := make([]byte, 180)
	if _, err := io.ReadFull(rng, r); err != nil {
		panic("RNG failure")
	}

	encryptedKey, _ := rsa.EncryptOAEP(sha256.New(), rng, &pk, r, nil)

	_, _ = out.Write(encryptedKey)

	key := r[0:32]
	iv := r[32:48]
	c, _ := aes.NewCipher(key)

	enc := cipher.NewCBCEncrypter(c, iv)

	b := make([]byte, enc.BlockSize()*256)[0:0]

	return &V{
		buf:      b,
		wholeBuf: b,
		enc:      enc,
		out:      out,
	}
}

func (v *V) Write(p []byte) (n int, err error) {
	remains := p

	for remains != nil {
		v.buf, remains = appendData(v.buf, remains)

		if len(v.buf) == cap(v.buf) {
			v.enc.CryptBlocks(v.buf, v.buf)
			_, err = v.out.Write(v.buf)
			if err != nil {
				return 0, err
			}
			v.buf = v.wholeBuf
		}
	}

	return len(p), nil
}

func (v *V) Close() error {
	padded, _ := pad(v.buf, v.enc.BlockSize())
	v.enc.CryptBlocks(padded, padded)
	_, err := v.out.Write(padded)
	v.buf = v.wholeBuf

	return err
}
