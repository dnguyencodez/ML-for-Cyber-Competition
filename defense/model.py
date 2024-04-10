from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.feature_selection import mutual_info_classif, SelectKBest
from sklearn.decomposition import PCA
import json
import os



class malware_detection_model():

    def __init__(self,
                 classifier=RandomForestClassifier(),
                 textual_extractor = 1,
                 ) -> None:
        
        self.classifier = classifier
        self.textual_extractor = CountVectorizer() if textual_extractor==1 else TfidfVectorizer(ngram_range=(2,2))
        
                     
