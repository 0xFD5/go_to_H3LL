package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// AES block size in bytes
const AESBlockSize = 16

// AES-128 S-box
var sBox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// Inverse S-box
var invSBox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

// Round constants
var rcon = [10]byte{
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
}

// Key schedule constants for AES-128
const (
	Nk = 4  // Number of 32-bit words in key
	Nr = 10 // Number of rounds
)

// AESCryptor provides encryption and decryption functionality
type AESCryptor struct {
	key []byte
}

// NewAESCryptor creates a new AESCryptor with a 16-byte key (AES-128)
func NewAESCryptor(key []byte) *AESCryptor {
	// Ensure key is exactly 16 bytes
	fixedKey := make([]byte, 16)
	copy(fixedKey, key)
	return &AESCryptor{key: fixedKey}
}

// GenerateKey creates a cryptographically secure random 16-byte key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// xorBytes XORs two byte slices of equal length
func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// subBytes applies the S-box to each byte of the state
func subBytes(state []byte) {
	for i := 0; i < len(state); i++ {
		state[i] = sBox[state[i]]
	}
}

// invSubBytes applies the inverse S-box to each byte of the state
func invSubBytes(state []byte) {
	for i := 0; i < len(state); i++ {
		state[i] = invSBox[state[i]]
	}
}

// shiftRows performs the row shifting transformation
func shiftRows(state []byte) {
	// Row 1: shift left by 1
	temp := state[1]
	state[1] = state[5]
	state[5] = state[9]
	state[9] = state[13]
	state[13] = temp

	// Row 2: shift left by 2
	temp = state[2]
	state[2] = state[10]
	state[10] = temp
	temp = state[6]
	state[6] = state[14]
	state[14] = temp

	// Row 3: shift left by 3
	temp = state[3]
	state[3] = state[15]
	state[15] = state[11]
	state[11] = state[7]
	state[7] = temp
}

// invShiftRows performs the inverse row shifting transformation
func invShiftRows(state []byte) {
	// Row 1: shift right by 1
	temp := state[13]
	state[13] = state[9]
	state[9] = state[5]
	state[5] = state[1]
	state[1] = temp

	// Row 2: shift right by 2
	temp = state[2]
	state[2] = state[10]
	state[10] = temp
	temp = state[6]
	state[6] = state[14]
	state[14] = temp

	// Row 3: shift right by 3
	temp = state[7]
	state[7] = state[11]
	state[11] = state[15]
	state[15] = state[3]
	state[3] = temp
}

// xtime multiplies by 2 in GF(2^8)
func xtime(x byte) byte {
	if x&0x80 != 0 {
		return (x << 1) ^ 0x1b
	}
	return x << 1
}

// mixColumns performs the column mixing transformation
func mixColumns(state []byte) {
	for i := 0; i < 4; i++ {
		s0 := state[4*i]
		s1 := state[4*i+1]
		s2 := state[4*i+2]
		s3 := state[4*i+3]

		state[4*i] = xtime(s0) ^ (s1 ^ xtime(s1)) ^ s2 ^ s3
		state[4*i+1] = s0 ^ xtime(s1) ^ (s2 ^ xtime(s2)) ^ s3
		state[4*i+2] = s0 ^ s1 ^ xtime(s2) ^ (s3 ^ xtime(s3))
		state[4*i+3] = (s0 ^ xtime(s0)) ^ s1 ^ s2 ^ xtime(s3)
	}
}

// invMixColumns performs the inverse column mixing transformation
func invMixColumns(state []byte) {
	for i := 0; i < 4; i++ {
		s0 := state[4*i]
		s1 := state[4*i+1]
		s2 := state[4*i+2]
		s3 := state[4*i+3]

		state[4*i] = multiply(s0, 0x0e) ^ multiply(s1, 0x0b) ^ multiply(s2, 0x0d) ^ multiply(s3, 0x09)
		state[4*i+1] = multiply(s0, 0x09) ^ multiply(s1, 0x0e) ^ multiply(s2, 0x0b) ^ multiply(s3, 0x0d)
		state[4*i+2] = multiply(s0, 0x0d) ^ multiply(s1, 0x09) ^ multiply(s2, 0x0e) ^ multiply(s3, 0x0b)
		state[4*i+3] = multiply(s0, 0x0b) ^ multiply(s1, 0x0d) ^ multiply(s2, 0x09) ^ multiply(s3, 0x0e)
	}
}

// multiply multiplies two elements in GF(2^8)
func multiply(x, y byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		if (y & 1) != 0 {
			result ^= x
		}
		x = xtime(x)
		y >>= 1
	}
	return result
}

// addRoundKey XORs the state with the round key
func addRoundKey(state []byte, key []byte) {
	for i := 0; i < len(state); i++ {
		state[i] ^= key[i]
	}
}

// keyExpansion expands the 16-byte key into 176 bytes of key schedule
func keyExpansion(key []byte) [][16]byte {
	var w [44][4]byte
	var roundKeys [11][16]byte

	// Copy key to first 4 words
	for i := 0; i < 4; i++ {
		w[i][0] = key[4*i]
		w[i][1] = key[4*i+1]
		w[i][2] = key[4*i+2]
		w[i][3] = key[4*i+3]
	}

	// Generate remaining words
	for i := 4; i < 44; i++ {
		temp := w[i-1]
		if i%4 == 0 {
			// Rotate
			temp[0], temp[1], temp[2], temp[3] = temp[1], temp[2], temp[3], temp[0]
			// SubBytes
			temp[0] = sBox[temp[0]]
			temp[1] = sBox[temp[1]]
			temp[2] = sBox[temp[2]]
			temp[3] = sBox[temp[3]]
			// XOR with Rcon
			temp[0] ^= rcon[i/4-1]
		}
		// XOR with previous column
		w[i][0] = w[i-4][0] ^ temp[0]
		w[i][1] = w[i-4][1] ^ temp[1]
		w[i][2] = w[i-4][2] ^ temp[2]
		w[i][3] = w[i-4][3] ^ temp[3]
	}

	// Copy to round keys
	for i := 0; i < 11; i++ {
		for j := 0; j < 16; j++ {
			roundKeys[i][j] = w[4*i+j/4][j%4]
		}
	}

	return roundKeys[:]
}

// aesEncryptBlock encrypts a single 16-byte block
func (c *AESCryptor) aesEncryptBlock(plaintext []byte) []byte {
	state := make([]byte, 16)
	copy(state, plaintext)

	// Key expansion
	roundKeys := keyExpansion(c.key)

	// Initial round
	addRoundKey(state, roundKeys[0][:])

	// Main rounds
	for round := 1; round < Nr; round++ {
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, roundKeys[round][:])
	}

	// Final round
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, roundKeys[Nr][:])

	return state
}

// aesDecryptBlock decrypts a single 16-byte block
func (c *AESCryptor) aesDecryptBlock(ciphertext []byte) []byte {
	state := make([]byte, 16)
	copy(state, ciphertext)

	// Key expansion
	roundKeys := keyExpansion(c.key)

	// Initial round
	addRoundKey(state, roundKeys[Nr][:])

	// Main rounds
	for round := Nr - 1; round > 0; round-- {
		invShiftRows(state)
		invSubBytes(state)
		addRoundKey(state, roundKeys[round][:])
		invMixColumns(state)
	}

	// Final round
	invShiftRows(state)
	invSubBytes(state)
	addRoundKey(state, roundKeys[0][:])

	return state
}

// pkcs7Pad adds PKCS#7 padding to the data
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, len(data)+padding)
	copy(padtext, data)
	for i := len(data); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}
	return padtext
}

// pkcs7Unpad removes PKCS#7 padding from the data
func pkcs7Unpad(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}
	padding := int(data[length-1])
	if padding > length || padding > AESBlockSize {
		return data
	}
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return data
		}
	}
	return data[:length-padding]
}

// EncryptWithIV encrypts plaintext using AES-CBC with PKCS#7 padding
func (c *AESCryptor) EncryptWithIV(plaintext []byte) ([]byte, []byte, error) {
	// Add padding
	paddedText := pkcs7Pad(plaintext, AESBlockSize)

	// Generate random IV
	iv := make([]byte, AESBlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	// CBC mode encryption
	ciphertext := make([]byte, len(paddedText))
	previous := make([]byte, AESBlockSize)
	copy(previous, iv)

	for i := 0; i < len(paddedText); i += AESBlockSize {
		block := paddedText[i : i+AESBlockSize]
		xored := xorBytes(block, previous)
		encrypted := c.aesEncryptBlock(xored)
		copy(ciphertext[i:i+AESBlockSize], encrypted)
		previous = encrypted
	}

	return ciphertext, iv, nil
}

// DecryptWithIV decrypts ciphertext using AES-CBC and removes PKCS#7 padding
func (c *AESCryptor) DecryptWithIV(ciphertext, iv []byte) []byte {
	// CBC mode decryption
	plaintext := make([]byte, len(ciphertext))
	previous := make([]byte, AESBlockSize)
	copy(previous, iv)

	for i := 0; i < len(ciphertext); i += AESBlockSize {
		block := ciphertext[i : i+AESBlockSize]
		decrypted := c.aesDecryptBlock(block)
		xored := xorBytes(decrypted, previous)
		copy(plaintext[i:i+AESBlockSize], xored)
		previous = block
	}

	// Remove padding
	return pkcs7Unpad(plaintext)
}

// SaveEncryptionDetails saves the encrypted data and key to a file
func SaveEncryptionDetails(filename string, key, iv, ciphertext []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write key, IV, and ciphertext in hex format
	fmt.Fprintf(file, "Key: %s\n", hex.EncodeToString(key))
	fmt.Fprintf(file, "IV: %s\n", hex.EncodeToString(iv))
	fmt.Fprintf(file, "Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	return nil
}

// LoadEncryptionDetails loads encryption details from a file
func LoadEncryptionDetails(filename string) ([]byte, []byte, []byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, nil, err
	}

	var keyHex, ivHex, ciphertextHex string
	fmt.Sscanf(string(data), "Key: %s\nIV: %s\nCiphertext: %s", &keyHex, &ivHex, &ciphertextHex)

	key, err1 := hex.DecodeString(keyHex)
	iv, err2 := hex.DecodeString(ivHex)
	ciphertext, err3 := hex.DecodeString(ciphertextHex)

	if err1 != nil || err2 != nil || err3 != nil {
		return nil, nil, nil, fmt.Errorf("decoding error")
	}

	return key, iv, ciphertext, nil
}
