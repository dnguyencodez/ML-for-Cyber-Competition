import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import os
import random

def split_dataset(directory_path, is_malware=1):

    X = [os.path.join(directory_path, item) for item in os.listdir(directory_path)]
    y = [is_malware] * len(X)


    X_train, X_test, y_train, y_test = train_test_split(
        X,y , random_state=104,test_size=0.3, shuffle=True
    )

    train_combined = list(zip(X_train, y_train))
    test_combined = list(zip(X_test, y_test))
    
    return train_combined, test_combined



def combine_and_shuffle(dataset1, dataset2):
    combined = dataset1 + dataset2
    random.shuffle(combined)

    datapoints, labels = zip(*combined)

    return datapoints, labels


if __name__=='__main__':
    benign_dir = '../../DikeDataset/files/benign'
    malware_dir = '../../DikeDataset/files/malware'

    benign_train, benign_test = split_dataset(benign_dir, 0)
    mal_train, mal_test = split_dataset(malware_dir)

    train_datapoints, train_labels = combine_and_shuffle(benign_train, mal_train)
    test_datapoints, test_labels = combine_and_shuffle(benign_test, mal_test)

    train_data = {
        'datapoints': train_datapoints,
        'labels': train_labels
    }

    test_data = {
        'datapoints': test_datapoints,
        'labels': test_labels
    }

    with open('train_data.json', 'w') as f:
            json.dump(train_data, f)

    with open('test_data.json', 'w') as f:
            json.dump(test_data, f)
