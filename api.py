from flask_cors import CORS
from flask import Flask, request, jsonify
import joblib
import numpy as np
from feature_extractor import extract_features

app = Flask(__name__)
CORS(app)
model = joblib.load('phishing_model.pkl')

feature_order = ['having_IP_Address', 'URL_Length', 'Shortining_Service',
    'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
    'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
    'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
    'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
    'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
    'Google_Index', 'Links_pointing_to_page', 'Statistical_report']

@app.route('/predict', methods=['GET'])
def predict():
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features_dict = extract_features(url)
    features_list = [features_dict.get(f, 0) for f in feature_order]
    features_array = np.array(features_list).reshape(1, -1)

    prediction = model.predict(features_array)
    result = "Phishing" if prediction[0] == 0 else "Legitimate"

    return jsonify({'url': url, 'result': result})

if __name__ == '__main__':
    app.run(debug=True, port=5000)