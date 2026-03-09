"""
ML Model Training Script for PhishShield
Trains email and URL phishing detection models
"""

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.preprocessing.text_cleaning import TextCleaner
from ml.feature_engineering.url_features import URLFeatureExtractor


def train_email_model():
    """Train email phishing detection model"""
    print("=" * 60)
    print("Training Email Phishing Detection Model")
    print("=" * 60)
    
    # Load dataset
    data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'phishing_emails_dataset.csv')
    print(f"Loading data from: {data_path}")
    
    df = pd.read_csv(data_path)
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    
    # Check column names and adjust
    text_col = None
    label_col = None
    
    for col in df.columns:
        if 'text' in col.lower() or 'email' in col.lower():
            text_col = col
        if 'type' in col.lower() or 'label' in col.lower() or 'class' in col.lower():
            label_col = col
    
    if not text_col or not label_col:
        print("Could not identify text and label columns")
        print("Available columns:", df.columns.tolist())
        return None
    
    print(f"Using text column: {text_col}")
    print(f"Using label column: {label_col}")
    
    # Prepare data
    texts = df[text_col].fillna('').astype(str)
    labels = df[label_col]
    
    # Convert labels to binary
    print(f"Label distribution:\n{labels.value_counts()}")
    
    # Map labels to binary (0 = safe, 1 = phishing)
    label_mapping = {}
    unique_labels = labels.unique()
    
    for label in unique_labels:
        label_str = str(label).lower()
        if 'phish' in label_str or 'spam' in label_str or 'malicious' in label_str:
            label_mapping[label] = 1
        else:
            label_mapping[label] = 0
    
    y = labels.map(label_mapping)
    print(f"Binary label distribution:\n{pd.Series(y).value_counts()}")
    
    # Clean text
    print("Cleaning text data...")
    cleaned_texts = texts.apply(TextCleaner.clean)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        cleaned_texts, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    
    # Create TF-IDF vectorizer
    print("Creating TF-IDF features...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        stop_words='english'
    )
    
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    print(f"TF-IDF feature matrix shape: {X_train_tfidf.shape}")
    
    # Train Logistic Regression model
    print("Training Logistic Regression model...")
    model = LogisticRegression(
        max_iter=1000,
        random_state=42,
        class_weight='balanced',
        C=1.0
    )
    
    model.fit(X_train_tfidf, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nTest Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))
    
    # Save model and vectorizer
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, 'email_model.pkl')
    vectorizer_path = os.path.join(models_dir, 'email_vectorizer.pkl')
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    
    print(f"\nModel saved to: {model_path}")
    print(f"Vectorizer saved to: {vectorizer_path}")
    
    return model, vectorizer


def train_url_model():
    """Train URL phishing detection model"""
    print("\n" + "=" * 60)
    print("Training URL Phishing Detection Model")
    print("=" * 60)
    
    # Load dataset
    data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'phishing_urls_dataset.csv')
    print(f"Loading data from: {data_path}")
    
    df = pd.read_csv(data_path)
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    
    # Identify columns
    url_col = None
    label_col = None
    
    for col in df.columns:
        if 'url' in col.lower():
            url_col = col
        if 'type' in col.lower() or 'label' in col.lower() or 'class' in col.lower():
            label_col = col
    
    if not url_col or not label_col:
        print("Could not identify URL and label columns")
        return None
    
    print(f"Using URL column: {url_col}")
    print(f"Using label column: {label_col}")
    
    # Prepare data
    urls = df[url_col].fillna('').astype(str)
    labels = df[label_col]
    
    print(f"Label distribution:\n{labels.value_counts()}")
    
    # Map labels to binary (0 = benign, 1 = phishing/defacement)
    label_mapping = {}
    unique_labels = labels.unique()
    
    for label in unique_labels:
        label_str = str(label).lower()
        if 'benign' in label_str or 'safe' in label_str:
            label_mapping[label] = 0
        else:
            label_mapping[label] = 1
    
    y = labels.map(label_mapping)
    print(f"Binary label distribution:\n{pd.Series(y).value_counts()}")
    
    # Extract features
    print("Extracting URL features...")
    feature_vectors = []
    
    for url in urls:
        features = URLFeatureExtractor.get_feature_vector(url)
        feature_vectors.append(features)
    
    X = np.array(feature_vectors)
    print(f"Feature matrix shape: {X.shape}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    
    # Train Random Forest model
    print("Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nTest Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))
    
    # Feature importance
    feature_names = URLFeatureExtractor.get_feature_names()
    importances = model.feature_importances_
    
    print("\nTop 10 Most Important Features:")
    indices = np.argsort(importances)[::-1][:10]
    for i in indices:
        print(f"  {feature_names[i]}: {importances[i]:.4f}")
    
    # Save model
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, 'url_model.pkl')
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"\nModel saved to: {model_path}")
    
    return model


def main():
    """Main training function"""
    print("PhishShield Model Training")
    print("=" * 60)
    
    # Train email model
    email_model = train_email_model()
    
    # Train URL model
    url_model = train_url_model()
    
    print("\n" + "=" * 60)
    print("Training Complete!")
    print("=" * 60)
    print("Models saved in ml/models/ directory")


if __name__ == "__main__":
    main()
