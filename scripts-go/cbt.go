package main

import (
	"archive/tar"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	inputDir := flag.String("input", "", "Input directory containing comic files")
	outputFile := flag.String("output", "", "Output .cbt file")
	password := flag.String("password", "", "Password for encryption (leave empty for no encryption)")
	flag.Parse()

	if *inputDir == "" || *outputFile == "" {
		fmt.Println("Usage: cbt-creator -input <directory> -output <file.cbt> [-password <password>]")
		os.Exit(1)
	}

	// Ensure output has .cbt extension
	if !strings.HasSuffix(strings.ToLower(*outputFile), ".cbt") {
		*outputFile += ".cbt"
	}

	var err error
	if *password != "" {
		err = createEncryptedCBT(*inputDir, *outputFile, *password)
		fmt.Printf("Created encrypted CBT: %s\n", *outputFile)
	} else {
		err = createUnencryptedCBT(*inputDir, *outputFile)
		fmt.Printf("Created unencrypted CBT: %s\n", *outputFile)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func createUnencryptedCBT(inputDir, outputPath string) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	tw := tar.NewWriter(outFile)
	defer tw.Close()

	// Collect all files
	var files []string
	err = filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Add files to tar
	for _, file := range files {
		relPath, err := filepath.Rel(inputDir, file)
		if err != nil {
			return err
		}

		// Read file
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}

		// Write tar header
		hdr := &tar.Header{
			Name: relPath,
			Mode: 0600,
			Size: int64(len(data)),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		// Write file data
		if _, err := tw.Write(data); err != nil {
			return err
		}

		fmt.Printf("Added: %s\n", relPath)
	}

	return nil
}

func createEncryptedCBT(inputDir, outputPath, password string) error {
	// Create temporary unencrypted tar
	tmpTar := outputPath + ".tmp"
	tmpFile, err := os.Create(tmpTar)
	if err != nil {
		return err
	}

	tw := tar.NewWriter(tmpFile)

	// Collect all files
	var files []string
	err = filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		tmpFile.Close()
		os.Remove(tmpTar)
		return err
	}

	// Add files to tar
	for _, file := range files {
		relPath, err := filepath.Rel(inputDir, file)
		if err != nil {
			tw.Close()
			tmpFile.Close()
			os.Remove(tmpTar)
			return err
		}

		// Read file
		data, err := os.ReadFile(file)
		if err != nil {
			tw.Close()
			tmpFile.Close()
			os.Remove(tmpTar)
			return err
		}

		// Write tar header
		hdr := &tar.Header{
			Name: relPath,
			Mode: 0600,
			Size: int64(len(data)),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			tw.Close()
			tmpFile.Close()
			os.Remove(tmpTar)
			return err
		}

		// Write file data
		if _, err := tw.Write(data); err != nil {
			tw.Close()
			tmpFile.Close()
			os.Remove(tmpTar)
			return err
		}

		fmt.Printf("Added: %s\n", relPath)
	}

	tw.Close()
	tmpFile.Close()

	// Read the tar file
	tarData, err := os.ReadFile(tmpTar)
	if err != nil {
		os.Remove(tmpTar)
		return err
	}

	fmt.Println("Encrypting...")

	// Encrypt
	key := deriveKey(password)
	encrypted, err := encryptAES(tarData, key)
	if err != nil {
		os.Remove(tmpTar)
		return err
	}

	// Write encrypted file
	err = os.WriteFile(outputPath, encrypted, 0644)
	os.Remove(tmpTar)

	return err
}

func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func encryptAES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Prepend IV to ciphertext
	return append(iv, ciphertext...), nil
}
