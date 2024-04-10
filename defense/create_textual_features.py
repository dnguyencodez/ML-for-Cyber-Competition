from sklearn.feature_extraction.text import CountVectorizer
from attribute_extractor import AttributeExtractor
import pandas as pd
import numpy as np
import json
import os
import argparse

DLL_LIST = []
API_LIST = []

# iterate through all files in a directory (benign or malware) and create unique feature list for bag of words during training
def create_feature_list(file_list):
    for f in file_list:
        with open(f, "rb") as file:
            pe_bytes = file.read() 

        att_extractor = AttributeExtractor(pe_bytes)

        if not att_extractor.pe:
            continue

        att_extractor.extract_dlls_and_api_calls()

        DLL_LIST.extend(att_extractor.dll_attributes)
        API_LIST.extend(att_extractor.api_attributes) 


if __name__=='__main__':

    # Creating DLL, API, and IFS1 feature sets
    f = open('./train_and_test_data/train_data.json')
    data = json.load(f)

    create_feature_list(data['datapoints'])

    unique_DLLs = list(set(DLL_LIST))
    unique_APIs = list(set(API_LIST))

    ifs1 = unique_APIs + unique_DLLs

    dll_api_ifs1 = {
        "DLLs": unique_DLLs,
        "APIs": unique_APIs,
        'ifs1': ifs1
    }

    with open('textual_features.json', 'w') as f:
        json.dump(dll_api_ifs1, f)

    




