# 🛡️ ML-Based Phishing URL Detector (Python)

URL ke features (length, IP host, suspicious words, risky TLD, entropy, etc.) nikal kar
**Random Forest** model se phishing / legitimate classify karta hai. Is mein CLI, Web UI aur JSON API teeno hain.

## Folder structure
```
phishing_url_detector/
├── features.py          # 28 URL features + brand/domain helpers
├── generate_dataset.py  # demo (synthetic) dataset banata hai
├── train.py             # model train, --compare (RF/GB/LogReg), metrics
├── detector.py          # ML + rule-based hybrid prediction (shared)
├── predict.py           # CLI tool (--json, --threshold)
├── app.py               # Flask web app + API
├── templates/           # 6 pages: dashboard, scan, bulk, history, model, learn (+ base.html)
├── static/style.css     # designer UI theme
├── db.py                # SQLite scan log
├── tests/test_all.py    # unit tests
├── data/  models/       # dataset aur trained model
└── requirements.txt
```

## Setup & Run
```bash
pip install -r requirements.txt
python generate_dataset.py          # demo data (ya apna real CSV use karo)
python train.py --compare           # model train (3 models compare)
python predict.py http://paypal-verify.xyz/login.php --json -t 0.4
python app.py                       # http://127.0.0.1:5000
python -m unittest discover -s tests -v
```

## Naya kya hai
- **Hybrid score**: final = 70% ML + 30% rule-based score (zyada robust, reasons bhi rules se aate hain)
- **Brand impersonation check**: `paypal.com.evil.xyz` jaisi URLs pakri jati hain (brand naam hai magar domain asli nahi)
- **Trusted domain list**: asli domains (registered domain match) low risk; `@`, IP, punycode trick par bypass nahi hota
- **Risk level** (LOW/MEDIUM/HIGH), ML aur rule score alag alag, adjustable **threshold** (strictness)
- **Naye features**: `brand_mismatch`, `path_depth`, `suspicious_ext`
- **API**: `/api/batch` (50 URLs), `/api/health`, `/api/metrics`
- **UI**: risk meter, strictness slider, recent history, light/dark theme
- **train.py --compare**: 5-fold CV, F1 / ROC-AUC, best model auto-save
- **CLI**: `--json`, `--threshold`, phishing milne par exit code 1

## API
```bash
curl -X POST http://127.0.0.1:5000/api/check -H "Content-Type: application/json" \
     -d '{"url":"http://secure-apple123.top/login"}'
```

```bash
curl -X POST http://127.0.0.1:5000/api/batch -H "Content-Type: application/json" \
     -d '{"urls":["https://github.com","http://45.33.12.9/paypal/login"],"threshold":0.5}'
```

## ⚠️ Real dataset use karo (zaroori)
`generate_dataset.py` ka data synthetic hai, is liye accuracy ~100% aati hai jo **real duniya mein nahi hogi**.
Asli project ke liye Kaggle ka "Phishing Site URLs" ya PhishTank dataset download karo, CSV mein
`url,label` columns rakho (label: 1/0 ya good/bad) aur chalao:
```bash
python train.py --data data/real_dataset.csv
```
Real data par 90-96% accuracy normal hai. Report mein confusion matrix aur top features likho.

## Improvement ideas
- Domain age (WHOIS) aur SSL certificate features add karo
- XGBoost / Logistic Regression se compare karo
- Browser extension banao jo ye API call kare

Note: trusted list mein `sites.google.com` jaise user-content subdomains bhi aa jate hain; asli use mein inhe alag handle karo.

## Disclaimer
Sirf educational/defensive use ke liye. Ye 100% guarantee nahi deta; asli security ke liye multiple layers use karo.
