# PhishEye — Local Development


## Setup (Linux / Windows / WSL)
1. Create venv: `python -m venv venv` and activate it.
2. Install requirements: `pip install -r requirements.txt`
3. Train model: `python model_train.py` (this creates `model.pkl`)
4. Run server: `python app.py`
5. Open http://127.0.0.1:5000 in your browser and paste a URL to test.


Notes:
- The `model_train.py` uses a small synthetic dataset shipped in `data/sample_urls.csv`. Replace with real labelled URLs to improve accuracy.
- For production, use Gunicorn/uvicorn and put behind a reverse proxy.