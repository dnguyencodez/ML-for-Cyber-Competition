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

        DLL_LIST.extend(att_extractor.attributes["DLLs"])
        API_LIST.extend(att_extractor.attributes["APIs"]) 


if __name__=='__main__':

    # parse command line arguments
    """
    Command format for creating DLL and API feature sets: python create_feature_sets.py
    Command format for creating IFS1: python create_feature_sets.py --ifs1
    """
    parser = argparse.ArgumentParser(description= 'Create each individual feature sets and integrated sets')
    parser.add_argument(
        '--ifs1',
        action=argparse.BooleanOptionalAction,
        # nargs= '+',
        help= 'If argument not included: creates individual DLL and API features, Else: creates IFS1',
    )
    args = parser.parse_args()
    create_ifs1 = args.ifs1
    
    

    # Creating DLL, API, and IFS1 feature sets
    if not create_ifs1:
        f = open('./train_and_test_data/train_data.json')
        data = json.load(f)

        create_feature_list(data['datapoints'])

        unique_DLLs = list(set(DLL_LIST))
        unique_APIs = list(set(API_LIST))

        unique_dlls_and_apis = {
            "DLLs": unique_DLLs,
            "APIs": unique_APIs
        }
        with open('dll_and_api_features.json', 'w') as f:
            json.dump(unique_dlls_and_apis, f)
    else:
        pass

    # Do something similar for headers, sections, and IFS2





