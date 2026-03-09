# PhishShield - AI-Powered Phishing Detection System

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**PhishShield** is a comprehensive, AI-powered phishing detection system that provides real-time analysis of emails, URLs, and websites to protect users from cyber threats. Using advanced machine learning algorithms and multi-layered security analysis, PhishShield delivers accurate threat detection with detailed explanations.

## 🌟 Key Features

- **Email Phishing Detection**: Advanced NLP-based analysis of email content using TF-IDF vectorization and Logistic Regression
- **URL Phishing Detection**: Structural URL analysis using Random Forest classification with 20+ engineered features
- **Website Safety Analysis**: Comprehensive multi-factor analysis including:
  - Domain intelligence (WHOIS, age, registrar)
  - SSL certificate validation
  - Reputation checking
  - ML-based predictions
- **Trust Score System**: 0-100 scoring with clear risk levels (Safe/Suspicious/Dangerous)
- **Web-based Interface**: Modern, responsive frontend with real-time analysis
- **RESTful API**: Easy integration with other applications
- **Trusted Domain Database**: Built-in whitelist of popular legitimate domains

## 🎯 Detection Accuracy

- **Email Model**: ~95% accuracy with Logistic Regression
- **URL Model**: ~96% accuracy with Random Forest
- **Analysis Time**: < 2 seconds per request
- **False Positive Reduction**: Trusted domain integration minimizes false alarms

## 📋 Table of Contents

- [Project Structure](#project-structure)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Model Training](#model-training)
- [Running the Application](#running-the-application)
- [API Documentation](#api-documentation)
- [Technology Stack](#technology-stack)
- [Dataset Information](#dataset-information)
- [Contributing](#contributing)
- [License](#license)

---

## 🗂️ Project Structure

```
phishing_detection_project/
├── data/                           # Dataset files for training
│   ├── Mendeley_Phishing_url_Dataset.csv
│   ├── PhiUSIIL_Phishing_URL_Dataset.csv
│   ├── Zenodo_phishing_email_dataset_CEAS_08.csv
│   ├── kaggle_Phishing_Email.csv
│   ├── kaggle_phishing_site_urls.csv
│   ├── phishing_urls_dataset.csv
│   └── trusted_domains.csv         # Whitelist of trusted domains
│
├── detection_engine/               # Core detection logic
│   ├── __init__.py
│   ├── domain_intelligence.py      # WHOIS, domain age, registrar analysis
│   ├── reputation_checker.py       # External reputation APIs
│   ├── ssl_checker.py              # SSL certificate validation
│   ├── trust_score.py              # Trust score calculation engine
│   ├── trusted_domains_loader.py   # Loads trusted domain whitelist
│   └── website_analyzer.py         # Main orchestrator for website analysis
│
├── frontend/                       # Web interface
│   ├── assets/                     # Images and static assets
│   ├── css/
│   │   └── style.css               # Application styles
│   ├── js/
│   │   ├── api.js                  # API client utilities
│   │   ├── dashboard.js            # Dashboard functionality
│   │   ├── emailAnalyzer.js        # Email analysis UI logic
│   │   ├── urlAnalyzer.js          # URL analysis UI logic
│   │   └── websiteAnalyzer.js      # Website analysis UI logic
│   └── pages/
│       ├── about.html              # About page
│       ├── awareness.html          # Security awareness education
│       ├── email.html              # Email scanner interface
│       ├── index.html              # Homepage
│       ├── url.html                # URL scanner interface
│       └── website.html            # Website checker interface
│
├── ml/                             # Machine learning components
│   ├── feature_engineering/
│   │   ├── email_features.py       # Email feature extraction (35+ features)
│   │   └── url_features.py         # URL feature extraction (20 features)
│   ├── models/                     # Trained model files (generated after training)
│   │   ├── email_model.pkl         # Email classification model
│   │   ├── email_vectorizer.pkl    # Email TF-IDF vectorizer
│   │   ├── url_model.pkl           # URL classification model
│   │   ├── url_model_lr.pkl        # URL Logistic Regression model
│   │   ├── url_model_rf.pkl        # URL Random Forest model
│   │   ├── url_model_xgb.pkl       # URL XGBoost model
│   │   └── url_scaler.pkl          # URL feature scaler
│   ├── preprocessing/
│   │   └── text_cleaning.py        # Text preprocessing for emails
│   ├── predictor.py                # Main prediction engine (600+ lines)
│   ├── train_comprehensive_url_model.py  # Advanced URL model training
│   ├── train_email_model.py        # Email model training script
│   └── train_models.py             # Combined model training script
│
├── server/                         # Backend server
│   ├── request_handler.py          # HTTP request routing and handling
│   └── server.py                   # HTTP server implementation
│
├── requirements.txt                # Python dependencies
├── run_server.py                   # Main application entry point
├── test_url_scanner.py             # Test scripts
└── README.md                       # This file
```

### Directory Explanations

#### `/data` - Datasets
Contains all CSV datasets used for training the ML models:
- **Email datasets**: Multiple sources for comprehensive email phishing detection
- **URL datasets**: Large-scale URL phishing datasets from reputable sources
- **Trusted domains**: Curated list of legitimate domains to reduce false positives

#### `/detection_engine` - Core Detection Logic
Multi-layered analysis engine that combines:
- **Domain Intelligence**: WHOIS lookup, domain age calculation, registrar verification
- **SSL Checker**: Certificate validation, expiry tracking, issuer verification
- **Reputation Checker**: External API integration for reputation signals
- **Trust Score Engine**: Weighted scoring system combining all signals
- **Website Analyzer**: Orchestrates all analysis components

#### `/frontend` - Web Interface
Modern, responsive web application:
- **Pages**: 6 HTML pages for different functionalities
- **CSS**: Custom styling with responsive design
- **JavaScript**: Client-side logic for API communication and UI updates

#### `/ml` - Machine Learning
Complete ML pipeline:
- **Feature Engineering**: Custom feature extractors for emails and URLs
- **Preprocessing**: Text cleaning, normalization, vectorization
- **Models**: Multiple trained models (Logistic Regression, Random Forest, XGBoost)
- **Predictor**: Production-ready prediction engine with singleton pattern

#### `/server` - Backend
HTTP server implementation:
- **Request Handler**: Routes API requests, handles CORS, serves static files
- **Server**: Multi-threaded HTTP server with graceful shutdown

---

## 🏗️ Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      User Interface                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Home    │  │  Email   │  │   URL    │  │ Website  │   │
│  │  Page    │  │ Scanner  │  │ Scanner  │  | Checker |   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    REST API Layer                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  /analyze-email  │  /analyze-url  │  /analyze-website│  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Application Core                            │
│  ┌────────────────────┐     ┌────────────────────┐         │
│  │  ML Predictor      │     │  Website Analyzer  │         │
│  │  ├─ Email Model    │     │  ├─ Domain Intel   │         │
│  │  ├─ URL Model      │     │  ├─ SSL Checker    │         │
│  │  └─ Vectorizer     │     │  ├─ Reputation     │         │
│  └────────────────────┘     │  └─ Trust Score    │         │
│                              └────────────────────┘         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Data Layer                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Trained      │  │ Trusted      │  │ External     │     │
│  │ Models (.pkl)│  │ Domains      │  │ APIs (WHOIS) │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Component Interaction Flow

#### Email Analysis Flow
```
User Input (Email) 
    → Frontend (email.html)
    → API Call (/analyze-email)
    → Request Handler
    → ML Predictor
        ├→ Text Cleaning
        ├→ TF-IDF Vectorization
        ├→ Feature Extraction (35+ features)
        └→ Logistic Regression Model
    → Risk Calculation
    → Response with Score & Explanation
```

#### URL Analysis Flow
```
User Input (URL)
    → Frontend (url.html)
    → API Call (/analyze-url)
    → Request Handler
    → ML Predictor
        ├→ Check Trusted Domains
        ├→ Feature Extraction (20 features)
        └→ Random Forest Model
    → Risk Calculation
    → Response with Score & Explanation
```

#### Website Analysis Flow (Most Comprehensive)
```
User Input (URL)
    → Frontend (website.html)
    → API Call (/analyze-website)
    → Request Handler
    → Website Analyzer
        ├→ Domain Intelligence
        │   ├→ WHOIS Lookup
        │   ├→ Domain Age Calculation
        │   └→ Registrar Analysis
        ├→ SSL Certificate Check
        │   ├→ Validity Verification
        │   ├→ Issuer Validation
        │   └→ Expiry Tracking
        ├→ Reputation Check
        │   └→ External API Queries
        ├→ ML Prediction
        │   └→ URL Model Analysis
        └→ Trust Score Engine
            ├→ Combine All Signals
            ├→ Calculate Weighted Score
            └→ Generate Recommendation
    → Comprehensive Response
```

### Trust Score Calculation

The trust score engine uses a weighted multi-factor approach:

```python
base_score = 100
total_impact = sum(signal['impact'] for signal in signals)

preliminary_score = base_score + total_impact

# Incorporate ML score (30% weight)
if ml_score is not None:
    ml_trust = 100 - ml_score  # Invert phishing probability
    final_score = (preliminary_score * 0.7) + (ml_trust * 0.3)

# Clamp to 0-100
trust_score = max(0, min(100, final_score))
```

**Signal Weights:**
- Domain Age: 25%
- SSL Certificate: 20%
- Reputation: 20%
- ML Prediction: 25%
- WHOIS Info: 10%

**Risk Levels:**
- **Safe (71-100)**: Legitimate content
- **Suspicious (31-70)**: Requires caution
- **Dangerous (0-30)**: High phishing probability

---

## 🚀 Installation

### Prerequisites

- **Python**: Version 3.8 or higher
- **pip**: Python package manager
- **RAM**: Minimum 4GB (8GB recommended for training)
- **Storage**: 500MB free space

### Step 1: Clone or Navigate to Project

```bash
cd c:\phishing_detection_project
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

**Dependencies include:**
- `scikit-learn>=1.3.0` - Machine learning framework
- `pandas>=2.0.0` - Data manipulation
- `numpy>=1.24.0` - Numerical computing
- `urllib3>=2.0.0` - HTTP library
- `python-whois>=0.8.0` - WHOIS lookups
- `dnspython>=2.4.0` - DNS resolution
- `requests>=2.31.0` - HTTP requests
- `certifi>=2023.7.22` - SSL certificates

---

## 🧠 Model Training

**IMPORTANT**: You must train the models before running the application!

### Quick Training (Recommended for First-Time Setup)

```bash
python ml/train_models.py
```

This script trains both email and URL models sequentially.

### Individual Model Training

#### Train Email Detection Model

```bash
python ml/train_email_model.py
```

**What it does:**
1. Loads email datasets from `/data`
2. Cleans text using `TextCleaner`
3. Extracts 35+ engineered features
4. Creates TF-IDF vectors (5000 features)
5. Trains Logistic Regression classifier
6. Saves `email_model.pkl` and `email_vectorizer.pkl`

**Expected Output:**
- Model accuracy: ~95%
- Training time: 2-5 minutes
- Output files: `ml/models/email_model.pkl`, `ml/models/email_vectorizer.pkl`

#### Train URL Detection Model

```bash
python ml/train_comprehensive_url_model.py
```

**What it does:**
1. Loads multiple URL datasets
2. Extracts 20 structural features per URL
3. Trains multiple models (RF, LR, XGBoost)
4. Applies feature scaling
5. Saves best performing model

**Expected Output:**
- Model accuracy: ~96%
- Training time: 5-10 minutes
- Output files: Multiple `.pkl` files in `ml/models/`

### Training Process Details

#### Email Model Training Steps

```python
# 1. Load dataset
df = pd.read_csv('data/phishing_emails_dataset.csv')

# 2. Prepare data
texts = df['text'].fillna('').astype(str)
labels = df['type'].map({'Safe': 0, 'Phishing': 1})

# 3. Clean text
cleaned_texts = texts.apply(TextCleaner.clean)

# 4. Create TF-IDF features
vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
X_tfidf = vectorizer.fit_transform(cleaned_texts)

# 5. Extract engineered features
engineered_features = EmailFeatureExtractor.get_feature_vector(text)

# 6. Combine features
X_combined = hstack([X_tfidf, engineered_features])

# 7. Train model
model = LogisticRegression(class_weight='balanced', max_iter=1000)
model.fit(X_combined, labels)
```

#### URL Model Training Steps

```python
# 1. Load dataset
df = pd.read_csv('data/phishing_urls_dataset.csv')

# 2. Extract features for each URL
for url in urls:
    features = URLFeatureExtractor.get_feature_vector(url)
    # 20 features including:
    # - url_length, domain_length
    # - has_ip_address, has_https
    # - suspicious_keywords_count
    # - subdomain_count, domain_entropy
    # - etc.

# 3. Train Random Forest
model = RandomForestClassifier(n_estimators=100, max_depth=20)
model.fit(X, labels)
```

### Verifying Training Success

After training completes, verify these files exist:

```
ml/models/
├── email_model.pkl          ✓
├── email_vectorizer.pkl     ✓
├── url_model.pkl            ✓
├── url_model_rf.pkl         ✓
├── url_model_lr.pkl         ✓
├── url_model_xgb.pkl        ✓
└── url_scaler.pkl           ✓
```

### Troubleshooting Training

**Issue**: "Dataset not found"
- **Solution**: Ensure CSV files are in `/data` directory

**Issue**: "Memory error"
- **Solution**: Reduce dataset size or increase system RAM

**Issue**: "Low accuracy"
- **Solution**: Check label mapping in training script, ensure proper class balance

---

## ▶️ Running the Application

### Start the Server

**Default (Port 8000):**
```bash
python run_server.py
```

**Custom Port:**
```bash
python run_server.py --port 8080
```

**Custom Host and Port:**
```bash
python run_server.py --host 127.0.0.1 --port 5000
```

### Access the Application

Once the server starts, you'll see:

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗███████╗██╗     ████████╗   ║
║   ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝██║     ██║    ██║  ║
║   ██████╔╝███████║██║███████╗███████║█████╗  ██║     ██║    ██║  ║
║   ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██╔══╝  ██║     ██║    ██║  ║
║   ██║     ██║  ██║██║███████║██║  ██║███████╗╚██████╗████████║    ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝    ║
║                                                                  ║
║        AI-Powered Email & URL Phishing Detection                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

============================================================
PhishShield Server Started
============================================================
Server running at http://0.0.0.0:8000
Frontend: http://localhost:8000

Press Ctrl+C to stop the server
============================================================
```

**Open your browser and navigate to:**
```
http://localhost:8000
```

### Available Pages

- **Homepage**: `http://localhost:8000` - Dashboard and overview
- **Email Scanner**: `http://localhost:8000/email.html` - Analyze emails
- **URL Scanner**: `http://localhost:8000/url.html` - Check URLs
- **Website Checker**: `http://localhost:8000/website.html` - Comprehensive analysis
- **Awareness**: `http://localhost:8000/awareness.html` - Security education
- **About**: `http://localhost:8000/about.html` - Project information

### Stopping the Server

Press `Ctrl+C` in the terminal to gracefully shutdown the server.

---

## 📡 API Documentation

### Base URL
```
http://localhost:8000
```

### Health Check

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "models_loaded": true
}
```

### Analyze Email

**Endpoint:** `POST /analyze-email`

**Request Body:**
```json
{
  "email": "Dear Customer,\n\nYour account has been compromised. Click here to verify: http://suspicious.com\n\nUrgent action required!",
  "subject": "Urgent: Account Verification"
}
```

**Response:**
```json
{
  "success": true,
  "type": "email",
  "score": 85,
  "trust_score": 15,
  "label": "Phishing",
  "risk_level": "Dangerous",
  "phishing_probability": 0.8923,
  "explanation": "This email exhibits characteristics commonly associated with phishing attempts. Specific indicators: contains urgent language (3 instances), uses suspicious keywords like 'verify', 'account', or 'password' (5 instances).",
  "indicators": [
    {"type": "warning", "message": "Urgent language detected (3 instances)"},
    {"type": "danger", "message": "Threatening language detected (2 instances)"}
  ]
}
```

### Analyze URL

**Endpoint:** `POST /analyze-url`

**Request Body:**
```json
{
  "url": "http://192.168.1.1/bank/verify/login.php"
}
```

**Response:**
```json
{
  "success": true,
  "type": "url",
  "trust_score": 12,
  "score": 88,
  "label": "Phishing",
  "risk_level": "Dangerous",
  "phishing_probability": 0.9145,
  "explanation": "This URL exhibits multiple characteristics commonly associated with phishing websites. Negative signals: URL uses IP address instead of domain name; Suspicious keywords detected (3); Connection is not encrypted.",
  "indicators": [
    {"type": "danger", "message": "URL uses IP address instead of domain name"},
    {"type": "warning", "message": "Suspicious keywords detected (3)"}
  ]
}
```

### Analyze Website (Comprehensive)

**Endpoint:** `POST /analyze-website`

**Request Body:**
```json
{
  "url": "https://suspicious-banking-site.com/login"
}
```

**Response:**
```json
{
  "success": true,
  "type": "website",
  "url": "https://suspicious-banking-site.com/login",
  "domain": "suspicious-banking-site.com",
  "trust_score": 18,
  "risk_level": "Dangerous",
  "confidence": "High",
  "positive_signals": [],
  "negative_signals": [
    {"category": "domain_age", "message": "Domain is only 15 days old", "impact": -25},
    {"category": "ssl", "message": "Self-signed certificate", "impact": -20},
    {"category": "ml_prediction", "message": "ML model detected 92% phishing probability", "impact": -42}
  ],
  "recommendation": {
    "title": "This website is likely dangerous",
    "actions": [
      "DO NOT visit this website",
      "Do not enter any credentials or personal information",
      "If you need the service, type the known legitimate address directly"
    ]
  },
  "domain_data": {
    "domain_age_days": 15,
    "registrar": "namecheap",
    "whois_hidden": true
  },
  "ssl_data": {
    "has_https": true,
    "certificate_valid": false,
    "issuer": "Self-Signed"
  },
  "ml_prediction": {
    "score": 92,
    "label": "Phishing",
    "probability": 0.92
  }
}
```

### Error Responses

**400 Bad Request:**
```json
{
  "error": "Email text is required"
}
```

**500 Internal Server Error:**
```json
{
  "error": "Analysis failed: Models not loaded"
}
```

---

## 🛠️ Technology Stack

### Backend
- **Language**: Python 3.8+
- **Web Framework**: Custom HTTP server (http.server)
- **Machine Learning**: scikit-learn
- **Data Processing**: pandas, numpy
- **Text Processing**: Regular expressions, TF-IDF vectorization

### Machine Learning
- **Email Classification**: Logistic Regression with TF-IDF
- **URL Classification**: Random Forest (100 estimators)
- **Feature Engineering**: Custom extractors (55+ total features)
- **Preprocessing**: Text cleaning, normalization, lemmatization

### Frontend
- **HTML5**: Semantic markup
- **CSS3**: Responsive design with flexbox/grid
- **JavaScript (ES6+)**: Vanilla JS, no frameworks
- **API Communication**: Fetch API

### Security Analysis
- **Domain Intelligence**: WHOIS protocol, DNS resolution
- **SSL Validation**: Certificate parsing
- **Reputation Checking**: External API integration
- **Trust Scoring**: Weighted multi-factor algorithm

### Data Management
- **Datasets**: CSV format (multiple sources)
- **Model Storage**: Pickle serialization
- **Trusted Domains**: CSV whitelist

---

## 📊 Dataset Information

### Email Datasets

1. **Zenodo_phishing_email_dataset_CEAS_08.csv** (66MB)
   - Source: CEAS 2008 Workshop
   - Contains: Legitimate and phishing emails
   - Format: Raw email text with labels

2. **kaggle_Phishing_Email.csv** (51MB)
   - Source: Kaggle community
   - Balanced classes for better accuracy

### URL Datasets

1. **PhiUSIIL_Phishing_URL_Dataset.csv** (55MB)
   - Comprehensive URL dataset
   - Includes structural features

2. **Mendeley_Phishing_url_Dataset.csv** (26MB)
   - Curated URL collection
   - Verified labels

3. **kaggle_phishing_site_urls.csv** (31MB)
   - Web-scraped URLs
   - Real-world examples

### Trusted Domains

**trusted_domains.csv** (10KB)
- Popular legitimate websites
- Reduces false positives
- Regularly updated

---

## 🔧 Configuration

### Server Configuration

Edit `run_server.py` to change defaults:

```python
parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
```

### Model Parameters

Adjust in training scripts:

**Email Model:**
```python
TfidfVectorizer(
    max_features=5000,      # Increase for more features
    ngram_range=(1, 2),     # Change n-gram range
    min_df=2,               # Minimum document frequency
    max_df=0.95             # Maximum document frequency
)

LogisticRegression(
    C=1.0,                  # Regularization strength
    max_iter=1000,          # Max iterations
    class_weight='balanced' # Handle class imbalance
)
```

**URL Model:**
```python
RandomForestClassifier(
    n_estimators=100,       # Number of trees
    max_depth=20,           # Tree depth
    class_weight='balanced' # Handle class imbalance
)
```

---

## 🧪 Testing

### Test URL Scanner

```bash
python test_url_scanner.py
```

### Manual API Testing

Using curl:

```bash
# Test email analysis
curl -X POST http://localhost:8000/analyze-email \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"Congratulations! You won $1000. Click here to claim.\", \"subject\": \"You won!\"}"

# Test URL analysis
curl -X POST http://localhost:8000/analyze-url \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://bit.ly/suspicious-link\"}"
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Areas for Contribution
- Additional ML models (Deep Learning, Transformers)
- More datasets for improved accuracy
- Frontend enhancements (React/Vue migration)
- API documentation improvements
- Security feature enhancements

### Contribution Guidelines

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Test thoroughly**: Ensure all functionality works
5. **Commit**: `git commit -m 'Add amazing feature'`
6. **Push**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

### Code Style
- Follow PEP 8 guidelines
- Add docstrings to all functions
- Include type hints where possible
- Write meaningful commit messages

---

## 📄 License

This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c) 2026 PhishShield

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👥 Authors & Acknowledgments

- **Development Team**: PhishShield Contributors
- **ML Models**: Based on research from CEAS, Kaggle, and academic datasets
- **Special Thanks**: Open-source community for excellent libraries

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review similar issues

## 🔮 Future Enhancements

Planned features:
- [ ] Browser extension (Chrome/Firefox)
- [ ] Email client plugins (Outlook/Gmail)
- [ ] Real-time URL monitoring
- [ ] Advanced threat intelligence feeds
- [ ] Multi-language support
- [ ] Mobile application (iOS/Android)
- [ ] Deep learning models (LSTM, BERT)
- [ ] API rate limiting and authentication
- [ ] Docker containerization
- [ ] Cloud deployment (AWS/Azure/GCP)

---

## ⚠️ Disclaimer

This tool provides automated analysis and should not replace human judgment. Always verify suspicious content through official channels. The developers are not responsible for any damages resulting from reliance on this tool's analysis.

**Remember**: No security tool is 100% accurate. Stay vigilant and practice good cybersecurity hygiene!

---

Made with ❤️ by the PhishShield Team | © 2026 All Rights Reserved
