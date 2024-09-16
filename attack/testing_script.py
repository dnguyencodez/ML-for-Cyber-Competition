import os
import requests
import pandas as pd

folder_path = 'D:/Yash-docs/Assignments-TAMU/ML/ML_model/ML-for-Cyber-Competition/attack/dropper_samples'  # Replace with your folder path

# Function to send requests
def send_request(file_path):
    url = "http://127.0.0.1:8080/"
    headers = {"Content-Type": "application/octet-stream"}
    with open(file_path, "rb") as file:
        response = requests.post(url, headers=headers, data=file.read())
    return response.text  # Assuming the response is text

# Iterate over files and collect results
results = []
for filename in os.listdir(folder_path):
    file_path = os.path.join(folder_path, filename)
    if os.path.isfile(file_path):  # Only process files, skip directories
        result = send_request(file_path)
        results.append({"filename": filename, "result": result})

# Convert to a Pandas DataFrame
df = pd.DataFrame(results)

# Save to Excel
df.to_excel("results.xlsx", index=False)