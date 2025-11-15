from flask import Flask, request, jsonify, render_template
import validators, tldextract, requests, re

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

def assess_phishing(url):
    score = 0
    reasons = []

    if not validators.url(url):
        return {"error": "Invalid URL"}

    domain_info = tldextract.extract(url)
    full_domain = f"{domain_info.domain}.{domain_info.suffix}"

    if re.search(r"(login|secure|update|verify|bank|account)", url, re.IGNORECASE):
        score += 30
        reasons.append("Suspicious keywords")

    if url.count("-") > 2 or len(url) > 100:
        score += 20
        reasons.append("Obfuscated or long URL")

    try:
        response = requests.get(url, timeout=3)
        if response.status_code != 200:
            score += 20
            reasons.append("Non-200 response")
    except:
        score += 30
        reasons.append("Unreachable or blocked")

    score = min(score, 100)
    return {
        "score": score,
        "domain": full_domain,
        "reasons": reasons
    }

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    result = assess_phishing(data.get("url", ""))
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
