import os
import struct

def read_dos_header(file_path):
    """Read the DOS header from a PE file"""
    with open(file_path, 'rb') as file:
        # Read the first 64 bytes which typically include the DOS header
        dos_header = file.read(64)
    return dos_header

def extract_dos_features(dos_header):
  """Extract features from the DOS header"""
  try:  
    # Unpack the first 2 bytes for 'e_magic' and the next 4 bytes for 'e_lfanew'
    e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, \
    e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid, e_oeminfo, e_res2, \
    e_lfanew = struct.unpack('<2sHHHHHHHHHHHH8sHHH16sI', dos_header[:60])
    return {
        'e_magic': e_magic,
        'e_cblp': e_cblp,
        'e_cp': e_cp,
        'e_crlc': e_crlc,
        'e_cparhdr': e_cparhdr,
        'e_minalloc': e_minalloc,
        'e_maxalloc': e_maxalloc,
        'e_ss': e_ss,
        'e_sp': e_sp,
        'e_csum': e_csum,
        'e_ip': e_ip,
        'e_cs': e_cs,
        'e_lfarlc': e_lfarlc,
        'e_ovno': e_ovno,
        'e_res': e_res,
        'e_oemid': e_oemid,
        'e_oeminfo': e_oeminfo,
        'e_res2': e_res2,
        'e_lfanew': e_lfanew
    }
  except struct.error as e:
        print(f"Error unpacking DOS header: {e}")

def analyze_goodware(folder_path):
    """Analyze all files in a folder and extract their DOS header features, skipping files with incomplete headers."""
    features = []
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            dos_header = read_dos_header(file_path)
            if dos_header:
                feature_data = extract_dos_features(dos_header)
                if feature_data:  # Ensure feature data is not None
                    features.append(feature_data)
            else:
                print(f"Skipping file with incomplete DOS header: {file_name}")
    return features


# Usage
# folder_path = 'path/to/goodware/files'
# goodware_features = analyze_goodware(folder_path)
# print(goodware_features)
