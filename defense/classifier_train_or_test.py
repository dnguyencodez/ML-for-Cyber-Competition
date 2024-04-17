from model import MalwareDetectionModel
from attribute_extractor import AttributeExtractor
import argparse
import json
import numpy as np
from joblib import dump, load
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedKFold
from xgboost import XGBClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.feature_extraction.text import TfidfVectorizer

def get_preprocessed_attributes(data_json_path):
    ifs2_atts = []
    ifs1_atts = []
    labels = [] 

    with open(data_json_path) as f:
        data = json.load(f)
    num_iterations = len(data['datapoints'])

    i = 1
    for filepath, label in zip(data['datapoints'], data['labels']):
        with open(filepath, "rb") as file:
            pe_bytes = file.read()
        
        extractor = AttributeExtractor(pe_bytes)
        if not extractor.pe:
            continue

        extractor.extract_header_fields()
        extractor.extract_sections_fields()
        extractor.extract_dlls_and_api_calls()

        dll = extractor.dll_attributes
        api = extractor.api_attributes
        ifs1_atts.append(dll + api)

        header_values = list(extractor.header_attributes.values())
        section_values = [value for section in extractor.section_attributes.values() for value in section.values()]
        ifs2_atts.append(header_values + section_values)

        labels.append(label) 

        if i % 20 == 0 or i == num_iterations:
            print(f"Extracted attributes of {i}/{num_iterations} PEs")

        i+=1

    # list of lists are inputted with sublists containing DLL and API names
    # need to concatenate names within each sublist to form strings
    ifs1_atts = [' '.join(atts) for atts in ifs1_atts]

    # convert to numpy array
    ifs2_atts = np.array(ifs2_atts)

    return ifs1_atts, ifs2_atts, labels

# from concurrent.futures import ThreadPoolExecutor, as_completed
# import os

# parallelize code to speed extraction
# def process_file(filepath, label):
#     try:
#         with open(filepath, "rb") as file:
#             pe_bytes = file.read()
        
#         extractor = AttributeExtractor(pe_bytes)
#         if not extractor.pe:
#             return None

#         extractor.extract_header_fields()
#         extractor.extract_sections_fields()
#         extractor.extract_dlls_and_api_calls()

#         dll = extractor.dll_attributes
#         api = extractor.api_attributes
#         ifs1_att = ' '.join(dll + api)

#         header_values = list(extractor.header_attributes.values())
#         section_values = [value for section in extractor.section_attributes.values() for value in section.values()]
#         ifs2_att = header_values + section_values

#         return ifs1_att, ifs2_att, label
#     except Exception as e:
#         print(f"Error processing {os.path.basename(filepath)}: {e}")
#         return None

# def get_preprocessed_attributes(data_json_path):
    # ifs1_atts = []
    # ifs2_atts = []
    # labels = []

    # with open(data_json_path) as f:
    #     data = json.load(f)

    # create a ThreadPoolExecutor to parallelize operations
    # with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    #     futures = [executor.submit(process_file, filepath, label) for filepath, label in zip(data['datapoints'], data['labels'])]

    #     for i, future in enumerate(as_completed(futures)):
    #         # print("here")
    #         result = future.result()
    #         if result:
    #             ifs1_att, ifs2_att, label = result
    #             ifs1_atts.append(ifs1_att)
    #             ifs2_atts.append(ifs2_att)
    #             labels.append(label)
            
    #         if (i + 1) % 20 == 0 or (i + 1) == len(data['datapoints']):
    #             print(f"Extracted attributes of {i + 1}/{len(data['datapoints'])} PEs")

    # return ifs1_atts, np.array(ifs2_atts), labels



def evaluate_model(y_true, y_pred, model_description):
    print(f"Performance of the model with {model_description}")
    print("-------------------------------------------------------")
    print("Accuracy:", accuracy_score(y_true, y_pred))
    print("Recall/TPR:", recall_score(y_true, y_pred))
    print("Precision:", precision_score(y_true, y_pred))
    print("F1 score:", f1_score(y_true, y_pred))

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    FPR = fp / (fp + tn)
    FNR = fn / (tp + fn)

    print("FPR:", FPR)
    print("FNR:", FNR)
    print()



if __name__=='__main__':
    # Parsing command line arguments
    parser = argparse.ArgumentParser(
        description="Train or test the model"
    )
    parser.add_argument(
        '--train',
        action=argparse.BooleanOptionalAction,
        help='Use this flag if you want to train the model.'
    )
    parser.add_argument(
        '--test',
        action=argparse.BooleanOptionalAction,
        help='Use this flag if you want to test the model.'
    )

    args = parser.parse_args()
    train_model = args.train
    test_model = args.test

    if train_model:
        print("Mode: Train Model")
        # Extract attributes
        print("Extracting attributes...")
        train_path = './train_and_test_data_updated/train_data.json'
        ifs1_atts, ifs2_atts, labels = get_preprocessed_attributes(train_path)

        # with open('../attributes/train_attributes.json') as f:
        #     atts = json.load(f)

        # ifs1_atts = atts['ifs1']
        # ifs2_atts = atts['ifs2']
        # labels = atts['labels']

        # save ifs1, ifs2, labels in case of training/testing error
        with open('train_attributes_updated.json', 'w') as f:
            json.dump({'ifs1': ifs1_atts, 'ifs2': ifs2_atts.tolist(), 'labels': labels}, f)


        # open vocabulary for bag of words
        with open('../attributes/vocabulary.json') as f:
            vocabulary = json.load(f)

        # train the model with 10-fold cross-validation
        print("Creating feature vectors and training the model...")
        skf = StratifiedKFold(n_splits=10)

        model = MalwareDetectionModel(
            vocabulary=vocabulary,
            classifier=XGBClassifier(),
            numerical_extractor=MinMaxScaler,
            textual_extractor=0 # using tf-idf
        )

        accuracies = []
        for train_index, test_index in skf.split(np.zeros(len(labels)), labels):  # Using labels to stratify
            # Splitting the data
            train_ifs1, test_ifs1 = [ifs1_atts[i] for i in train_index], [ifs1_atts[i] for i in test_index]
            train_ifs2, test_ifs2 = ifs2_atts[train_index], ifs2_atts[test_index]
            train_labels, test_labels = labels[train_index], labels[test_index]

            # Fit the model on the training data
            model.fit(train_ifs1, train_ifs2, train_labels)

            # Predict on the test set
            predictions = model.predict(test_ifs1, test_ifs2)

            # Evaluate and store each fold's performance
            accuracies.append(accuracy_score(test_labels, predictions))
        # model.fit(ifs1_atts, ifs2_atts, labels)
        print("Model is trained")
        print(f'Average Accuracy: {np.mean(accuracies)}')

        # save the model
        dump(model, 'malware_detection_model_updated.joblib')
        print('Model is saved')


    if test_model:
        print("Mode: Test Model")
        # Extract attributes
        print("Extracting attributes...")
        test_path = '../train_and_test_data/test_data.json'
        ifs1_atts, ifs2_atts, labels = get_preprocessed_attributes(test_path)

        # save ifs1, ifs2, labels in case of testing error
        with open('test_attributes_updated.json', 'w') as f:
            json.dump({'ifs1': ifs1_atts, 'ifs2': ifs2_atts.tolist(), 'labels': labels}, f)

        # evaluate model
        model = load('malware_detection_model.joblib')
        y_pred = model.predict(ifs1_atts, ifs2_atts)
        y_pred_threshold = model.predict_threshold(ifs1_atts, ifs2_atts)

        evaluate_model(labels, y_pred, "standard predictions")
        evaluate_model(labels, y_pred_threshold, "threshold predictions")



    if not train_model and not test_model:
        print("No training or testing done, please pass the proper argument.")