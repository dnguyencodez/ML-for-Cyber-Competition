from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.feature_selection import mutual_info_classif, SelectKBest
from sklearn.decomposition import PCA
import json
import os

data_directory = 'train_and_test_data'  # Replace with the name of your folder

# Lists to store the content of the JSON files
train_data = []
test_data = []

# Loop through the files in the directory
for filename in os.listdir(data_directory):
    if filename.endswith('.json'):  # Check if the file is a JSON file
        file_path = os.path.join(data_directory, filename)
        
        # Open and read the content of the JSON file
        with open(file_path, 'r') as file:
            data = json.load(file)
            
            # Check if the filename indicates that the data is for training or testing
            if 'train' in filename:
                train_data.append(data)
            elif 'test' in filename:
                test_data.append(data)

class malware_detection_model():

    def __init__(self,
                 classifier=RandomForestClassifier(),
                 textual_extractor = 1,
                 ) -> None:
        
        self.classifier = classifier
        self.textual_extractor = CountVectorizer() if textual_extractor==1 else TfidfVectorizer(ngram_range=(2,2))
        
                     
