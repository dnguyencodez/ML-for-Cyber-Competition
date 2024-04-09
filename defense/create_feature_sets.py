from sklearn.feature_extraction.text import CountVectorizer
from attribute_extractor import AttributeExtractor
import pandas as pd
import numpy as np
import json
import os

DLL_LIST = []
API_LIST = []

# iterate through all files in a directory (benign or malware) and create unique feature list for bag of words during training
def create_feature_list(directory_path):
    for item in os.listdir(directory_path):
        pe_file_path = os.path.join(directory_path, item)

        # print(pe_file_path)

        with open(pe_file_path, "rb") as file:
            pe_bytes = file.read()

        att_extractor = AttributeExtractor(pe_bytes)

        if not att_extractor.pe:
            continue

        att_extractor.extract_dlls_and_api_calls()

        DLL_LIST.extend(att_extractor.attributes["DLLs"])
        API_LIST.extend(att_extractor.attributes["APIs"])


if __name__=='__main__':
    benign_dir = '../../DikeDataset/files/benign'
    malware_dir = '../../DikeDataset/files/malware'

    create_feature_list(benign_dir)
    create_feature_list(malware_dir)

    unique_DLLs = list(set(DLL_LIST))
    unique_APIs = list(set(API_LIST))

    unique_dlls_and_apis = {
        "DLLs": unique_DLLs,
        "APIs": unique_APIs
    }
    with open('dll_and_api_features.json', 'w') as f:
        json.dump(unique_dlls_and_apis, f)

    # print(DLL_LIST)


