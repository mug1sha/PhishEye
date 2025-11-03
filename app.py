from flask import Flask, request, jsonify, render_template, send_from_directory
import joblib
from analyzer import analyze_url, extract_features
import os


app = Flask(__name__, static_folder='static', template_folder='static')


MODEL_FILE = 'model.pkl'
model = None


if os.path.exists(MODEL_FILE):
    model = joblib.load(MODEL_FILE)
else:
    print('Warning: model.pkl not found. Analysis will use rule-based scoring only.')


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/analyze_url', methods=['POST'])
def api_analyze():
    data = request.get_json() or {}
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400


    # rule-based analysis
    rule_score, reasons = analyze_url(url)


    # ML model score
    ml_score = None
    if model is not None:
        features = extract_features(url)
        # model expects 2D array
        try:
            prob = model.predict_proba([features])[0][1]
            ml_score = float(prob)
        except Exception as e:
            ml_score = None


    # combine scores (simple average when both exist)
    if ml_score is None:
        combined = rule_score
    else:
        combined = (rule_score + ml_score) / 2.0


    result = {
            'url': url,
            'rule_score': round(rule_score, 3),
            'ml_score': round(ml_score, 3) if ml_score is not None else None,
            'combined_score': round(combined, 3),
            'reasons': reasons
    }
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)