package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var encryptionKey = []byte("clave_de_encriptacion")

func caesarEncrypt(text string, shift int) string {
	encrypted := strings.Builder{}
	shift = shift % 26 // Para evitar valores de desplazamiento mayores a 26

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

func encryptFile(filePath string, shift int, key []byte) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	encryptedData := caesarEncrypt(string(data), shift)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext := aesgcm.Seal(nil, iv, []byte(encryptedData), nil)

	encryptedFileData := append(iv, ciphertext...)

	newFilePath := strings.TrimSuffix(filePath, filepath.Ext(filePath)) + ".encrypted"
	err = ioutil.WriteFile(newFilePath, encryptedFileData, 0644)
	if err != nil {
		return err
	}

	err = os.Remove(filePath)
	if err != nil {
		fmt.Println("No se pudo eliminar el archivo original:", err)
	}

	return nil
}

func decryptFile(filePath string, shift int, key []byte) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return err
	}

	decryptedData := caesarEncrypt(string(plaintext), -shift)

	newFilePath := strings.TrimSuffix(filePath, ".encrypted") // Eliminar la extensión .encrypted
	err = ioutil.WriteFile(newFilePath, []byte(decryptedData), 0644)
	if err != nil {
		return err
	}

	err = os.Remove(filePath)
	if err != nil {
		fmt.Println("No se pudo eliminar el archivo encriptado:", err)
	}

	return nil
}

func main() {
	folderPath := ""
	extension := ".txt"
	shift := 3

	files, err := ioutil.ReadDir(folderPath)
	if err != nil {
		fmt.Println("Error al leer la carpeta:", err)
		return
	}

	fmt.Print("Ingrese el código de acceso para desencriptar los archivos: ")
	var accessCode string
	fmt.Scanln(&accessCode)

	if accessCode == "tu_clave_secreta" {
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".encrypted") {
				filePath := folderPath + "/" + file.Name()
				err := decryptFile(filePath, shift, encryptionKey)
				if err != nil {
					fmt.Println("Error al desencriptar el archivo", filePath, ":", err)
				} else {
					fmt.Println("Archivo desencriptado:", strings.TrimSuffix(filePath, ".encrypted"))
				}
			} else if strings.HasSuffix(file.Name(), extension) {
				filePath := folderPath + "/" + file.Name()
				err := encryptFile(filePath, shift, encryptionKey)
				if err != nil {
					fmt.Println("Error al encriptar el archivo", filePath, ":", err)
				} else {
					fmt.Println("Archivo encriptado:", filePath+".encrypted")
				}
			}
		}
	} else {
		fmt.Println("Código de acceso incorrecto. No se puede desencriptar.")
	}
}
