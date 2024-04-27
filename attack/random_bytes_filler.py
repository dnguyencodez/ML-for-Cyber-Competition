import os
import random
import shutil
import analyze_goodware

def append_unused_data(filepath, size=256):
    """ Append random bytes to the end of the file. """
    with open(filepath, "ab") as f:
        f.write(os.urandom(size))

def process_directory(directory):
    """ Process each file in the directory. """
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            # if filepath.endswith('.bin'):  # Only process binary files
            print(f"Processing {filepath}")
            # Create a new directory to store modified files
            output_directory = os.path.join(directory, "modified_files")
            os.makedirs(output_directory, exist_ok=True)
            # Copy the original file to the new directory
            shutil.copy(filepath, output_directory)
            # Get the path of the copied file in the new directory
            new_filepath = os.path.join(output_directory, file)
            # Modify the copied file
            append_unused_data(new_filepath)

if __name__ == "__main__":
    input_directory = "D:/Yash-docs/Assignments-TAMU\ML\ML_model/ML-for-Cyber-Competition/attack/evade1"
    process_directory(input_directory)
    print("Usage: python script.py <directory>")
