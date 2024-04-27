import os
import random
import shutil

def append_unused_data(filepath, size=256):
    """ Append random bytes to the end of the file. """
    with open(filepath, "ab") as f:
        f.write(os.urandom(size))

def process_directory(directory, new_directory):
    """ Process each file in the directory. """
    if not os.path.exists(new_directory):
        os.makedirs(new_directory)  # Create the new directory if it doesn't exist

    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if filepath.endswith('.bin'):  # Only process binary files
                print(f"Processing {filepath}")
                # Copy the file to the new directory
                new_filepath = shutil.copy(filepath, os.path.join(new_directory, file))
                # Modify the copied file
                append_unused_data(new_filepath)
if __name__ == "__main__":
    input_directory = "D:/Yash-docs/Assignments-TAMU/ML/ML_model\ML-for-Cyber-Competition/attack/evade1"
    output_directory = "D:/Yash-docs/Assignments-TAMU/ML/ML_model\ML-for-Cyber-Competition/attack/evade2"
    process_directory(input_directory, output_directory)
    print(f"Usage: python script.py {input_directory} {output_directory}")
