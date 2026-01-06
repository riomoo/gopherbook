#!/bin/bash

# CBT (Comic Book Tar) Creator and Extractor
# Creates and extracts .cbt files with optional AES encryption
# Compatible with Go server encryption format

set -e

show_usage() {
    echo "Usage:"
    echo "  Create:  $0 create -i <input_directory> -o <output_file> [-p <password>]"
    echo "  Extract: $0 extract -i <input_file> -o <output_directory> [-p <password>]"
    echo ""
    echo "Options:"
    echo "  -i    Input directory/file"
    echo "  -o    Output file/directory"
    echo "  -p    Password for encryption/decryption (optional)"
    echo ""
    echo "Examples:"
    echo "  $0 create -i ./comics -o mycomic.cbt"
    echo "  $0 create -i ./comics -o mycomic.cbt -p mysecretpass"
    echo "  $0 extract -i mycomic.cbt -o ./extracted"
    echo "  $0 extract -i mycomic.cbt -o ./extracted -p mysecretpass"
    echo ""
    exit 1
}

# Parse command line arguments
MODE="$1"
shift || show_usage

INPUT=""
OUTPUT=""
PASSWORD=""

while getopts "i:o:p:h" opt; do
    case $opt in
        i) INPUT="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        h) show_usage ;;
        *) show_usage ;;
    esac
done

# Validate mode
if [ "$MODE" != "create" ] && [ "$MODE" != "extract" ]; then
    echo "Error: First argument must be 'create' or 'extract'"
    show_usage
fi

# Validate required arguments
if [ -z "$INPUT" ] || [ -z "$OUTPUT" ]; then
    echo "Error: Input and output are required"
    show_usage
fi

# Encrypt data using AES-CFB
encrypt_data() {
    local input_file="$1"
    local output_file="$2"
    local password="$3"

    # Derive key using SHA256 (same as Go)
    local key=$(echo -n "$password" | sha256sum | cut -d' ' -f1 | xxd -r -p | base64)

    # Generate random IV (16 bytes for AES)
    local iv=$(openssl rand -base64 16)

    # Encrypt using AES-256-CFB
    # First write IV, then encrypted data
    echo -n "$iv" | base64 -d > "$output_file"
    openssl enc -aes-256-cfb -K "$(echo -n "$password" | sha256sum | cut -d' ' -f1)" -iv "$(echo -n "$iv" | base64 -d | xxd -p -c 256)" -in "$input_file" >> "$output_file"
}

# Decrypt data using AES-CFB (compatible with Go implementation)
decrypt_data() {
    local input_file="$1"
    local output_file="$2"
    local password="$3"

    # Extract IV (first 16 bytes)
    local iv_hex=$(head -c 16 "$input_file" | xxd -p -c 256)

    # Extract ciphertext (rest of file)
    tail -c +17 "$input_file" > "${output_file}.tmp"

    # Decrypt using AES-256-CFB
    if ! openssl enc -d -aes-256-cfb -K "$(echo -n "$password" | sha256sum | cut -d' ' -f1)" -iv "$iv_hex" -in "${output_file}.tmp" -out "$output_file" 2>/dev/null; then
        rm -f "${output_file}.tmp"
        return 1
    fi

    rm -f "${output_file}.tmp"
    return 0
}

# CREATE MODE
create_cbt() {
    INPUT_DIR="$INPUT"
    OUTPUT_FILE="$OUTPUT"

    # Check if input directory exists
    if [ ! -d "$INPUT_DIR" ]; then
        echo "Error: Input directory '$INPUT_DIR' does not exist"
        exit 1
    fi

    # Ensure output has .cbt extension
    if [[ ! "$OUTPUT_FILE" =~ \.cbt$ ]]; then
        OUTPUT_FILE="${OUTPUT_FILE}.cbt"
    fi

    # Create unencrypted tar archive
    echo "Creating tar archive from $INPUT_DIR..."
    TMP_TAR=$(mktemp)

    # Create tar file, preserving relative paths
    tar -cf "$TMP_TAR" -C "$INPUT_DIR" .

    # List files that were added
    echo ""
    echo "Files added:"
    tar -tf "$TMP_TAR"
    echo ""

    if [ -n "$PASSWORD" ]; then
        # Encrypted mode
        echo "Encrypting with AES-CFB (Go-compatible format)..."

        encrypt_data "$TMP_TAR" "$OUTPUT_FILE" "$PASSWORD"

        rm "$TMP_TAR"
        echo "Created encrypted CBT: $OUTPUT_FILE"
    else
        # Unencrypted mode - just move the tar file
        mv "$TMP_TAR" "$OUTPUT_FILE"
        echo "Created unencrypted CBT: $OUTPUT_FILE"
    fi

    echo "Done!"
}

# EXTRACT MODE
extract_cbt() {
    INPUT_FILE="$INPUT"
    OUTPUT_DIR="$OUTPUT"

    # Check if input file exists
    if [ ! -f "$INPUT_FILE" ]; then
        echo "Error: Input file '$INPUT_FILE' does not exist"
        exit 1
    fi

    # Create output directory if it doesn't exist
    mkdir -p "$OUTPUT_DIR"

    TMP_TAR=$(mktemp)

    # Check if file is encrypted by trying to read as tar first
    if tar -tf "$INPUT_FILE" >/dev/null 2>&1; then
        # File is unencrypted tar
        cp "$INPUT_FILE" "$TMP_TAR"
    else
        # File appears to be encrypted
        if [ -z "$PASSWORD" ]; then
            echo "Error: File appears to be encrypted. Please provide password with -p flag."
            rm "$TMP_TAR"
            exit 1
        fi

        echo "Decrypting $INPUT_FILE..."

        if ! decrypt_data "$INPUT_FILE" "$TMP_TAR" "$PASSWORD"; then
            echo "Error: Failed to decrypt. Wrong password or corrupted file."
            exit 1
        fi

        echo "Decryption successful!"
    fi

    # Extract tar archive
    echo "Extracting to $OUTPUT_DIR..."

    if tar -xf "$TMP_TAR" -C "$OUTPUT_DIR" 2>/dev/null; then
        echo ""
        echo "Files extracted:"
        tar -tf "$TMP_TAR"
        echo ""
        echo "Extraction complete!"
    else
        rm "$TMP_TAR"
        echo "Error: Failed to extract. File may be corrupted."
        exit 1
    fi

    rm "$TMP_TAR"
}

if [ "$MODE" = "create" ]; then
    create_cbt
elif [ "$MODE" = "extract" ]; then
    extract_cbt
fi
