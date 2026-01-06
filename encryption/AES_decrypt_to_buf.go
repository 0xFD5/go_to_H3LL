package encryption

func Decrypt() []byte {

	filename := "encryption_details.txt"
	loadedKey, loadedIV, loadedCiphertext, err := LoadEncryptionDetails(filename)
	if err != nil {
		panic(err)
	}

	//you can directly include your encryption_details as a hex string in here
	//keyHex := "abcd123"
	//ivHex := "fd5"
	//ciphertextHex := "c1fered"
	//loadedKey, err1 := hex.DecodeString(keyHex)
	//loadedIV, err2 := hex.DecodeString(ivHex)
	//ciphertext, err3 := hex.DecodeString(ciphertextHex) //ENCRYPTED PAYLOAD

	// Create new cryptor with loaded key
	decryptor := NewAESCryptor(loadedKey)

	// Decrypt

	buf := decryptor.DecryptWithIV(loadedCiphertext, loadedIV)
	return buf
}
