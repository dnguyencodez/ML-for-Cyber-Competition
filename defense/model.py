from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_selection import mutual_info_classif, SelectKBest
from sklearn.decomposition import PCA
import json

class malware_detection_model():

    def __init__(self,
                 classifier=RandomForestClassifier(),
                 textual_extractor = CountVectorizer(),
                 ) -> None:
        
        self.classifier = classifier
        self.textual_extractor = textual_extractor