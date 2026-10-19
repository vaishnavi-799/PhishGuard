# PhishGuard ML Service (FastAPI + XGBoost + SHAP)

Predicts whether a URL is phishing and explains why.

```
ml-service/
  app/             FastAPI app (main.py), request/response schemas, PredictionService, model bundle I/O
  features/        URL + optional security feature extraction (single feature schema used by training AND serving)
  preprocessing/   CSV validation/cleaning, feature matrix building
  training/        split, fit, evaluate, train CLI, synthetic data generator
  analysis/        cybersecurity analysis engine: URL, DNS/RDAP, TLS, website, typosquatting, homograph, brand, risk (docs_analysis.md)
  explainability/  SHAP (TreeExplainer) explanations, with a labelled fallback
  models/          trained artifacts (created by training; not committed)
  data/            CSV schema docs + synthetic sample
  tests/           unit + integration tests
```

## Setup
```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt                           # Python 3.10+
```

## Train
```bash
# 1) your real dataset (schema: data/README.md)
python -m training.train --data data/your_dataset.csv --output-dir models

# 2) or smoke-test the pipeline on SYNTHETIC data (metrics are meaningless)
python -m training.generate_sample_data --rows 3000 --out data/sample/synthetic_urls.csv
python -m training.train --data data/sample/synthetic_urls.csv --output-dir models
```
Pipeline: validate CSV -> extract features -> **domain-grouped, stratified** 80/20 split -> XGBoost (early stopping on a slice of the
training split only) -> evaluate on the untouched test split -> save `models/model.json`, `metadata.json`, `metrics.json`.

Reported on the test split: accuracy, precision, recall, F1, ROC-AUC, confusion matrix (plus Brier score). Every value is computed
from the model's predictions on that run. `metadata.json` also records library versions, dataset SHA-256, parameters and feature list,
and states loudly when the data was synthetic. `--algorithm hist_gbm` swaps XGBoost for scikit-learn's HistGradientBoosting; it is only a
fallback for machines without XGBoost and produces `occlusion` rather than SHAP explanations.

## Serve
```bash
cp .env.example .env     # set ML_API_KEY; the Node backend sends it in the X-API-Key header
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Bind to localhost / a private network: this service is meant to be called by the backend, not by browsers.

```bash
curl -s localhost:8000/predict -H 'Content-Type: application/json' -H "X-API-Key: $ML_API_KEY" -d '{
  "url": "http://paypa1-secure-login.xyz/verify/account",
  "security_features": {"domain_age_days": 3, "threat_feed_hits": 3},
  "top_k": 5
}'
```
Response (`explain: false` omits the explanation fields):
```json
{
  "prediction": "phishing",
  "probability": 0.0,
  "confidence": 0.0,
  "top_features": [{"feature": "...", "label": "...", "value": 0.0, "contribution": 0.0, "direction": "phishing"}],
  "explanation": ["... raises phishing risk (+0.00)"],
  "model_version": "xgboost-<timestamp>",
  "explanation_method": "shap_tree",
  "ignored_features": []
}
```
(`0.0` placeholders: the values come from the loaded model.) Other endpoints: `GET /health` (open), `GET /model` (metadata + test metrics).
Without a trained model `/predict` returns **503**; it never invents an answer.

### Field meanings
* `probability` = the model's P(phishing). Classification uses the threshold stored with the model (default 0.5).
* `confidence` = `|2p-1| x (0.5 + 0.5 x share of model inputs that were available)`. A heuristic reliability indicator, **not** a calibrated statistical confidence.
* `contribution` = log-odds impact (positive pushes toward phishing). Only features the caller actually provided are listed.
* `explanation_method`: `shap_tree` (SHAP TreeExplainer, XGBoost) or `occlusion` (fallback: replace the feature with its training median and measure the change in log-odds). Occlusion is cruder: with saturated probabilities or correlated features it can produce counter-intuitive signs, so treat it as indicative only.

## Test
```bash
python -m unittest discover -s tests -t .      # or: pytest
```
Covers feature extraction, CSV validation, split leakage, evaluation maths, train -> save -> load round-trip, checksum tamper
detection, a **label-shuffle test** (a model trained on shuffled labels must score near chance, proving predictions are learned, not
hard-coded), the service contract, and the HTTP API (skipped when FastAPI is not installed).

## Security notes
* `model.json` (XGBoost) is plain JSON; `hist_gbm` models use joblib/pickle: **only load model directories you trust**. The loader verifies a SHA-256 of the model file.
* The full URL is never logged (URLs can contain tokens); only the host is.
* The analysis is static: no URL is fetched by this service.

## Known limitations
* Brand and keyword lists in `features/url_features.py` are small heuristics used as *features*; the model decides how much they matter. Registered-domain parsing uses a short built-in suffix list: use the Public Suffix List (`tldextract`) for production accuracy.
* No probability calibration yet; there is no concept-drift monitoring. Retrain regularly on fresh data.
* Real-world accuracy is unknown until you train and evaluate on a real labelled dataset.

## Analysis engine
`POST /analyze` runs the full cybersecurity analysis (and the ML model when one is loaded) and returns one normalized JSON report.
See [docs_analysis.md](docs_analysis.md). Run its tests with the same command as above (they use local fake DNS/HTTP/TLS servers and
generated certificates, so no internet access is needed).
