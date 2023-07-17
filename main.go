package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
	"os"
	"path/filepath"
)

func encryptFile(filename string, key []byte) error {
	// Abrir el archivo original
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Crear un archivo temporal para almacenar los datos encriptados
	tempFile, err := os.Create(filename + ".enc")
	if err != nil {
		return err
	}
	defer tempFile.Close()

	// Crear el bloque AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Generar un vector de inicialización único
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Escribir el vector de inicialización en el archivo temporal
	if _, err := tempFile.Write(iv); err != nil {
		return err
	}

	// Crear el modo de cifrado en CBC
	stream := cipher.NewCFBEncrypter(block, iv)

	// Leer el archivo original y encriptar los datos
	buffer := make([]byte, 4096)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		encryptedData := make([]byte, n)
		stream.XORKeyStream(encryptedData, buffer[:n])
		if _, err := tempFile.Write(encryptedData); err != nil {
			return err
		}
	}

	// Eliminar el archivo original
	if err := os.Remove(filename); err != nil {
		return err
	}

	// Renombrar el archivo temporal al nombre original
	if err := os.Rename(filename+".enc", filename); err != nil {
		return err
	}

	return nil
}

func encryptFolder(folderPath string, key []byte) error {
	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			err := encryptFile(path, key)
			if err != nil {
				log.Printf("Error encriptando archivo %s: %v\n", path, err)
			} else {
				log.Printf("Archivo %s encriptado exitosamente\n", path)
			}
		}
		return nil
	})
	return err
}

func main() {
	folderPath := "/ruta/a/carpeta"                            // Ruta a la carpeta que deseas encriptar
	key := []byte("clave_de_encriptacion_de_16_24_o_32_bytes") // Clave de encriptación AES (16, 24 o 32 bytes)

	err := encryptFolder(folderPath, key)
	if err != nil {
		log.Fatalf("Error encriptando carpeta: %v\n", err)
	}

	log.Println("Carpeta encriptada exitosamente")
}
