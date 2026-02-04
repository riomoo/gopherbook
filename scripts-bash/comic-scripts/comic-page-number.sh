#!/bin/bash

# --- Configuration ---
# Set the directory containing your comic book images
IMAGE_DIR="./"

# Set the name of the file to save the output to
OUTPUT_FILE="pages_xml_output.txt"

# --- Script Start ---

# Check if the image directory exists
if [ ! -d "$IMAGE_DIR" ]; then
    echo "Error: Directory '$IMAGE_DIR' not found." >&2
    echo "Please create the directory and place your images inside, or update the IMAGE_DIR variable." >&2
    exit 1
fi

# Ensure the output file is clear or create it
> "$OUTPUT_FILE"

# Start the <Pages> tag
echo "            <Pages>" >> "$OUTPUT_FILE"

# Initialize a counter for the <Page Image="..."> attribute
page_counter=0

# Use 'find' to get a list of image files, sort them numerically (important for comic order)
# Adjust the pattern (*.jpg|*.jpeg|*.png) to match your file types if necessary
find "$IMAGE_DIR" -maxdepth 1 -type f -regex ".*\.\(jpg\|jpeg\|png\|jxl\|avif\)$" | sort -V | while read -r image_path; do
    
    # 1. Get the ImageSize in bytes
    # Use 'stat' with a format to get the size in bytes (the command might differ slightly on non-Linux systems like macOS)
    # Linux (GNU stat): %s
    # macOS (BSD stat): %z
    
    # Simple cross-platform attempt (often works):
    # FALLBACK: If the 'stat' command is complex or fails, a simple 'wc -c' (byte count) can be used.
    # We will try 'stat' for better compatibility with typical setups.

    file_size_bytes=$(stat -c%s "$image_path" 2>/dev/null || wc -c < "$image_path")
    
    # 2. Determine if it's the first page (for Type="FrontCover")
    if [ "$page_counter" -eq 0 ]; then
        # This is the cover page (Page Image="0")
        xml_line="                <Page Image=\"${page_counter}\" ImageSize=\"${file_size_bytes}\" Type=\"FrontCover\"/>"
    else
        # Subsequent pages
        xml_line="                <Page Image=\"${page_counter}\" ImageSize=\"${file_size_bytes}\"/>"
    fi
    
    # 3. Print the generated XML line
    echo "$xml_line" >> "$OUTPUT_FILE"
    
    # 4. Increment the counter
    ((page_counter++))

done

# End the <Pages> tag
echo "            </Pages>" >> "$OUTPUT_FILE"

echo "---"
echo "✅ Script completed."
echo "Generated $page_counter <Page> entries and saved the output to: $OUTPUT_FILE"
echo "You can now paste the content of '$OUTPUT_FILE' into your ComicInfo.xml file."
echo "---"

# Optional: Display the content of the generated file
cat "$OUTPUT_FILE"
