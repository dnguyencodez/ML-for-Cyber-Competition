import os
import lief

def extract_features(file_path):
    pe = lief.parse(file_path)
    features = dict()
    # print(pe)

    if pe is not None:
        # Extracting DOS Header features
        dos_header = pe.dos_header
        features["dos_header"] = { 
            key: (getattr(dos_header, key, 'Not available') if getattr(dos_header, key, 'Not available') is not None else 'Not available') for key in dir(dos_header) if not key.startswith('__') 
        }

        # Extracting Header features
        header = pe.header
        features["header"] = {
            key: (getattr(header, key, 'Not available') if getattr(header, key, 'Not available') is not None else 'Not available') for key in dir(header) if not key.startswith('__') 
        }

        # Extracting Optional Header features
        optional_header = pe.optional_header
        features["optional_header"] = {
            key: (getattr(optional_header, key, 'Not available') if getattr(optional_header, key, 'Not available') is not None else 'Not available') for key in dir(optional_header) if not key.startswith('__') and not callable(getattr(optional_header, key))
        }

        # Extracting Section features
        features["sections"] = [sec.name for sec in pe.sections if sec is not None] or 'Not available'

        # Extracting Import features
        features["imports"] = [imp.name for imp in pe.imports if imp is not None] or 'Not available'

        # Extracting Export features
        features["exports"] = [exp.name for exp in pe.exported_functions if exp is not None] if pe.has_exports else 'Not available'

        # Extracting Resources
        # features["resources"] = [res.id for res in pe.resources if res is not None] if pe.has_resources else 'Not available'
    else:
        features = 'Not available'

    return features

def process_directory(directory_path):
    features_list = []
    for file_name in os.listdir(directory_path):
        # if file_name.endswith(".pe"):
            file_path = os.path.join(directory_path, file_name)
            features = extract_features(file_path)
            features_list.append(features)
    print(features_list)
    return features_list

# Use the function
features = process_directory("D:\Yash-docs\Assignments-TAMU\ML\ML_model\ML-for-Cyber-Competition\defense\datasets\gw1")