package webshell

// 冰蝎 / 哥斯拉用到的对称加密原语。全部为 AES-128 + PKCS#7，密钥一律是 16 字节
// ASCII（md5(口令) 的前 16 位十六进制字符）；XOR 也是按这 16 个字符循环。

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

var errCipherLen = errors.New("密文长度不是块大小的整数倍")

func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	return append(b, bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, errCipherLen
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, errCipherLen
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errCipherLen
		}
	}
	return b[:len(b)-n], nil
}

func aesECBEncrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src := pkcs7Pad(plain, block.BlockSize())
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += block.BlockSize() {
		block.Encrypt(dst[i:i+block.BlockSize()], src[i:i+block.BlockSize()])
	}
	return dst, nil
}

func aesECBDecrypt(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return nil, errCipherLen
	}
	dst := make([]byte, len(ct))
	for i := 0; i < len(ct); i += block.BlockSize() {
		block.Decrypt(dst[i:i+block.BlockSize()], ct[i:i+block.BlockSize()])
	}
	return pkcs7Unpad(dst, block.BlockSize())
}

func aesCBCEncrypt(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, errCipherLen
	}
	src := pkcs7Pad(plain, block.BlockSize())
	dst := make([]byte, len(src))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	return dst, nil
}

func aesCBCDecrypt(key, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return nil, errCipherLen
	}
	dst := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, ct)
	return pkcs7Unpad(dst, block.BlockSize())
}

// xorRing 复刻各家马里的 `key[i+1 & 15]`：XOR 对称，加密解密同一函数。
func xorRing(data, key []byte, offset int) []byte {
	out := make([]byte, len(data))
	n := len(key)
	for i := range data {
		out[i] = data[i] ^ key[(i+offset)%n]
	}
	return out
}
