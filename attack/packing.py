import os
import subprocess
import random

def upx_pack(input_file, output_file):
    """Packs a binary file using UPX."""
    try:
        result = subprocess.run(["upx", "-9", "-o", output_file, input_file], check=True)
        if result.returncode == 0:
            print(f"Packed {input_file} into {output_file}")
        else:
            print(f"UPX failed to pack {input_file}: {result.stderr}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error packing file {input_file}: {str(e)}")
        return False
    return True

def simple_obfuscate(binary_path):
    """Obfuscates a binary by modifying non-essential bytes."""
    try:
        with open(binary_path, 'r+b') as f:
            data = bytearray(f.read())
            last_percent_index = int(len(data) * 0.99)
            for _ in range(10):
                index = random.randint(last_percent_index, len(data) - 1)
                data[index] = data[index] ^ random.randint(1, 255)
            f.seek(0)
            f.write(data)
        print(f"Obfuscated {binary_path}")
    except FileNotFoundError:
        print(f"File not found: {binary_path}")
    except Exception as e:
        print(f"Failed to obfuscate {binary_path}: {str(e)}")

def process_binaries(input_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for filename in os.listdir(input_dir):
        input_path = os.path.join(input_dir, filename)
        # output_filename = os.path.splitext(filename)[0] + ".exe"
        output_path = os.path.join(output_dir, filename)
        if upx_pack(input_path, output_path):
            simple_obfuscate(output_path)
        else:
            print(f"Skipping obfuscation for {filename} due to packing error.")

if __name__ == "__main__":
    input_directory = "./evade1"
    output_directory = "./modified_files"
    process_binaries(input_directory, output_directory)
