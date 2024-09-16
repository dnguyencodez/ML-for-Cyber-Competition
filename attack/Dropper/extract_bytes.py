import base64
import os

XOR_KEY = 0x73

def encode_bytes(input_file, output_file):
    try:
        # Open the binary file in binary read mode
        with open(input_file, 'rb') as f:
            # Read all bytes from the file
            byte_data = f.read()
        
        # Encode the byte string using Base64
        base64_encoded = base64.b64encode(byte_data)
        
        # Convert the Base64 encoded string to bytes
        base64_bytes = base64_encoded.decode('utf-8').encode('utf-8')
        
        # XOR the bytes with XOR_KEY
        xor_bytes = bytes(byte ^ XOR_KEY for byte in base64_bytes)
        
        # Write the XOR'ed bytes directly to a binary file
        with open(output_file, 'wb') as f:
            f.write(xor_bytes)
        
        print("Encoded bytes saved to", output_file)
    
    except Exception as e:
        print("An error occurred:", e)

def process_directory(input_dir, output_dir):
    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # File counter for naming
    file_counter = 1
    
    # Process each file in the directory
    for filename in os.listdir(input_dir):
        file_path = os.path.join(input_dir, filename)
        if os.path.isfile(file_path):
            # Construct the output file name using the counter
            output_path = os.path.join(output_dir, f"{file_counter}.bin")
            encode_bytes(file_path, output_path)
            file_counter += 1

# Example usage:
input_directory = "D:/Dropper/Dropper/Dropper/Set-3"  # Replace with your directory path
output_directory = "D:/Dropper/Dropper/Dropper/new_binaries"  # Output directory path

process_directory(input_directory, output_directory)
