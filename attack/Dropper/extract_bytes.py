import base64

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
        
        # Write the XOR'ed bytes to the output file as a C-style array
        with open(output_file, 'w') as f:

            for byte in xor_bytes[:-1]:
                f.write(str(byte) + ", ")
            f.write(str(xor_bytes[-1]))
        
        print("Encoded bytes saved to", output_file)
    
    except FileNotFoundError:
        print("Input file not found.")
    except Exception as e:
        print("An error occurred:", e)

# Example usage:
input_file = "calc.exe"  # Replace with your input exe file path
output_file = "out.txt"  # Output file path

encode_bytes(input_file, output_file)
