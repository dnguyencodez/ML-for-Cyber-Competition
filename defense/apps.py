from flask import Flask, jsonify, request
from attribute_extractor import AttributeExtractor
from model import MalwareDetectionModel
from joblib import load

def create_app(model, threshold):
    app = Flask(__name__)
    app.config['model'] = model

    # analyse a sample
    @app.route('/', methods=['POST']) 
    def post():
        # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
        if request.headers['Content-Type'] != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            return resp
        
        pe_bytes = request.data
        
        try:
            # initialize feature extractor with bytez
            extractor = AttributeExtractor(pe_bytes=pe_bytes)

            # extract pe attributes and preprocess them for input into classifier
            ifs1, ifs2 = extractor.extract_and_preprocess()
            model = app.config['model']

            # query the model
            result = int(model.predict_threshold(ifs1, ifs2, threshold)[0])
            print('LABEL = ', result)
            # print(type(result))
        
        except Exception as e:
            print("Error:", e)
            result = 1

        if not isinstance(result, int) or result not in {0, 1}:
            resp = jsonify({'error': 'unexpected model result (not in [0,1])'})
            resp.status_code = 500  # Internal Server Error
            return resp

        resp = jsonify({'result': result})
        resp.status_code = 200
        return resp
    
    return app

if __name__ == '__main__':
    # load the model
    # model = load('malware_detection_model_updated.joblib') # this is the best model
    model = load('final_model.joblib') # model for extras: tf-idf normalization, optimal threshold computation

    threshold = 0.4366852343082428

    # Create app with the loaded model and threshold
    app = create_app(model, threshold)

    # run the app
    app.run(host='0.0.0.0', port=8080)  # use 0.0.0.0 to make the server publicly available