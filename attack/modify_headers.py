import os
import struct
import numpy as np
from analyze_goodware import analyze_goodware

def read_dos_header(file_path):
    """Read the DOS header from a PE file"""
    with open(file_path, 'rb') as file:
        dos_header = file.read(64)
    return dos_header

def write_dos_header(file_path, new_header):
    """Write the modified DOS header back to the file"""
    with open(file_path, 'r+b') as file:  # Open for reading and writing binary
        file.write(new_header)

def calculate_median_features(features_list):
    """Calculate the median values for features in the list of dictionaries, excluding non-numeric values and handling None entries."""
    median_values = {}
    # Iterate over each key assuming the first valid entry has all keys (if any features are non-empty)
    if features_list:
        for key in features_list[0].keys():
            try:
                # Collect values that are either int or float and not None
                numeric_values = [float(features[key]) for features in features_list if features and isinstance(features[key], (int, float))]
                if numeric_values:
                    median_values[key] = int(np.median(numeric_values))
            except ValueError:
                # Handle or log the error if conversion fails or simply skip non-numeric data
                print(f"Skipping non-numeric key: {key}")
            except TypeError:
                # Handle cases where features might be None
                print(f"Skipping NoneType entry for key: {key}")
    return median_values



def modify_dos_header(original_header, median_values):
    """Modify the DOS header with median values, ensuring the buffer is correctly handled."""
    if len(original_header) < 60:
        print("Received an incomplete header, cannot modify.")
        return None

    # Ensure that the unpack string is set to process exactly 60 bytes
    original_values = struct.unpack('<2sHHHHHHHHHHHH8sHHH16sI', original_header)
    modified_values = (
        original_values[0],  # e_magic remains unchanged
        median_values['e_cblp'],
        median_values['e_cp'],
        median_values['e_crlc'],
        median_values['e_cparhdr'],
        median_values['e_minalloc'],
        median_values['e_maxalloc'],
        median_values['e_ss'],
        median_values['e_sp'],
        median_values['e_csum'],
        median_values['e_ip'],
        median_values['e_cs'],
        median_values['e_lfarlc'],
        original_values[13],  # e_ovno might be specific to the file
        original_values[14],  # e_res stays the same
        median_values['e_oemid'],
        median_values['e_oeminfo'],
        original_values[17],  # e_res2 stays the same
        median_values['e_lfanew']
    )

    # Pack the modified values back into bytes
    new_header = struct.pack('<2sHHHHHHHHHHHH8sHHH16sI', *modified_values)
    return new_header

def modify_malware_headers(malware_folder, median_values):
    """Modify all malware files in a folder to have headers matching the median goodware values"""
    for file_name in os.listdir(malware_folder):
        file_path = os.path.join(malware_folder, file_name)
        if os.path.isfile(file_path):
            original_header = read_dos_header(file_path)
            new_header = modify_dos_header(original_header, median_values)
            write_dos_header(file_path, new_header)

# Usage
goodware_folder = 'D:/Yash-docs/Assignments-TAMU/ML/ML_model\ML-for-Cyber-Competition/attack/datasets/gw1'
malware_folder = 'D:/Yash-docs/Assignments-TAMU/ML/ML_model/ML-for-Cyber-Competition/attack/evade1'

goodware_features = analyze_goodware(goodware_folder)  # Assumes this function is defined as in the previous script
median_values = calculate_median_features(goodware_features)

modify_malware_headers(malware_folder, median_values)
