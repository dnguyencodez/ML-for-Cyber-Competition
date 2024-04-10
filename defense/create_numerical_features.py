import json
from attribute_extractor import AttributeExtractor

header_data = []
section_data = []
ifs2_features = []

f = open('./train_and_test_data/train_data.json')
data = json.load(f)

for f in data['datapoints']:
    with open(f, "rb") as file:
        pe_bytes = file.read() 
    
    extractor = AttributeExtractor(pe_bytes)

    if not extractor.pe:
            continue

    extractor.extract_header_fields()
    extractor.extract_sections_fields()

    # collect and flatten header and section values
    header_values = list(extractor.header_attributes.values())
    section_values = [value for section in extractor.section_attributes.values() for value in section.values()]
    
    header_data.append(header_values)
    section_data.append(section_values)
    ifs2_features.append(header_values + section_values)

header_section_ifs2 = {
    'header': header_data,
    'sections': section_data,
    'ifs2': ifs2_features
}

with open('numerical_features.json', 'w') as f:
    json.dump(header_section_ifs2, f)