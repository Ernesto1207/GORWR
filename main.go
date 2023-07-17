package main

import (
	"fmt"
	"strings"
)

func caesarEncrypt(text string, shift int) string {
	encrypted := strings.Builder{}
	shift = shift % 26

	for _, char := range text {
		if char >= 'a' && char <= 'z' {
			encrypted.WriteByte(byte((int(char-'a')+shift)%26 + 'a'))
		} else if char >= 'A' && char <= 'Z' {
			encrypted.WriteByte(byte((int(char-'A')+shift)%26 + 'A'))
		} else {
			encrypted.WriteByte(byte(char))
		}
	}

	return encrypted.String()
}

func caesarDecrypt(encryptedText string, shift int) string {
	return caesarEncrypt(encryptedText, -shift)
}

func main() {
	plaintext := "Hola, este es un mensaje secreto!"
	shift := 3
	encrypted := caesarEncrypt(plaintext, shift)
	fmt.Println("Mensaje encriptado:", encrypted)

	decrypted := caesarDecrypt(encrypted, shift)
	fmt.Println("Mensaje desencriptado:", decrypted)
}
