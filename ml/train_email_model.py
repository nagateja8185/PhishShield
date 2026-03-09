"""
Email Phishing Detection Model Training
Combines multiple datasets and trains an optimized ML model
"""

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import sys
import re

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.preprocessing.text_cleaning import TextCleaner
from ml.feature_engineering.email_features import EmailFeatureExtractor


def load_and_combine_datasets():
    """Load and combine multiple email datasets"""
    print("=" * 60)
    print("Loading Email Datasets")
    print("=" * 60)
    
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    all_emails = []
    all_labels = []
    all_subjects = []
    
    # Load Kaggle Phishing Email Dataset
    kaggle_path = os.path.join(data_dir, 'kaggle_Phishing_Email.csv')
    if os.path.exists(kaggle_path):
        print(f"\nLoading Kaggle dataset: {kaggle_path}")
        df_kaggle = pd.read_csv(kaggle_path)
        print(f"  Shape: {df_kaggle.shape}")
        
        # Map labels: Phishing Email -> 1, Safe Email -> 0
        df_kaggle['label'] = df_kaggle['Email Type'].map({
            'Phishing Email': 1,
            'Safe Email': 0
        })
        
        all_emails.extend(df_kaggle['Email Text'].fillna('').tolist())
        all_labels.extend(df_kaggle['label'].tolist())
        all_subjects.extend([''] * len(df_kaggle))  # No subject in this dataset
        print(f"  Added {len(df_kaggle)} emails")
    
    # Load Zenodo CEAS Dataset
    zenodo_path = os.path.join(data_dir, 'Zenodo_phishing_email_dataset_CEAS_08.csv')
    if os.path.exists(zenodo_path):
        print(f"\nLoading Zenodo CEAS dataset: {zenodo_path}")
        df_zenodo = pd.read_csv(zenodo_path)
        print(f"  Shape: {df_zenodo.shape}")
        
        # Combine subject and body for full email text
        email_texts = []
        for idx, row in df_zenodo.iterrows():
            subject = str(row.get('subject', ''))
            body = str(row.get('body', ''))
            full_text = f"Subject: {subject}\n\n{body}" if subject else body
            email_texts.append(full_text)
        
        all_emails.extend(email_texts)
        all_labels.extend(df_zenodo['label'].tolist())
        all_subjects.extend(df_zenodo['subject'].fillna('').tolist())
        print(f"  Added {len(df_zenodo)} emails")
    
    print(f"\n{'=' * 60}")
    print(f"Total combined emails: {len(all_emails)}")
    print(f"Label distribution:")
    label_counts = pd.Series(all_labels).value_counts().sort_index()
    print(f"  Safe (0): {label_counts.get(0, 0)}")
    print(f"  Phishing (1): {label_counts.get(1, 0)}")
    
    return all_emails, all_labels, all_subjects


def extract_combined_features(emails, subjects):
    """Extract both TF-IDF and engineered features"""
    print("\n" + "=" * 60)
    print("Extracting Features")
    print("=" * 60)
    
    # Clean text for TF-IDF
    print("Cleaning text data...")
    cleaned_emails = []
    for email in emails:
        cleaned = TextCleaner.clean(str(email))
        cleaned_emails.append(cleaned)
    
    # Extract engineered features
    print("Extracting engineered features...")
    engineered_features = []
    for i, (email, subject) in enumerate(zip(emails, subjects)):
        features = EmailFeatureExtractor.get_feature_vector(email, subject)
        engineered_features.append(features)
        
        if (i + 1) % 10000 == 0:
            print(f"  Processed {i + 1}/{len(emails)} emails")
    
    engineered_features = np.array(engineered_features)
    print(f"Engineered features shape: {engineered_features.shape}")
    
    return cleaned_emails, engineered_features


def train_model(cleaned_emails, engineered_features, labels):
    """Train email phishing detection model"""
    print("\n" + "=" * 60)
    print("Training Model")
    print("=" * 60)
    
    # Split data
    indices = np.arange(len(cleaned_emails))
    train_idx, test_idx = train_test_split(
        indices, test_size=0.2, random_state=42, stratify=labels
    )
    
    X_train_text = [cleaned_emails[i] for i in train_idx]
    X_test_text = [cleaned_emails[i] for i in test_idx]
    X_train_eng = engineered_features[train_idx]
    X_test_eng = engineered_features[test_idx]
    y_train = [labels[i] for i in train_idx]
    y_test = [labels[i] for i in test_idx]
    
    print(f"Training samples: {len(X_train_text)}")
    print(f"Test samples: {len(X_test_text)}")
    
    # Create TF-IDF vectorizer
    print("\nCreating TF-IDF features...")
    vectorizer = TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        stop_words='english'
    )
    
    X_train_tfidf = vectorizer.fit_transform(X_train_text)
    X_test_tfidf = vectorizer.transform(X_test_text)
    
    print(f"TF-IDF feature matrix shape: {X_train_tfidf.shape}")
    
    # Combine TF-IDF with engineered features
    from scipy.sparse import hstack, csr_matrix
    
    X_train_eng_sparse = csr_matrix(X_train_eng)
    X_test_eng_sparse = csr_matrix(X_test_eng)
    
    X_train_combined = hstack([X_train_tfidf, X_train_eng_sparse])
    X_test_combined = hstack([X_test_tfidf, X_test_eng_sparse])
    
    print(f"Combined feature matrix shape: {X_train_combined.shape}")
    
    # Train Logistic Regression model
    print("\nTraining Logistic Regression model...")
    model = LogisticRegression(
        max_iter=1000,
        random_state=42,
        class_weight='balanced',
        C=1.0,
        solver='lbfgs'
    )
    
    model.fit(X_train_combined, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_combined)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n{'=' * 60}")
    print("Model Performance")
    print(f"{'=' * 60}")
    print(f"Test Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"                 Safe  Phishing")
    print(f"Actual Safe      {cm[0,0]:4d}  {cm[0,1]:4d}")
    print(f"Actual Phishing  {cm[1,0]:4d}  {cm[1,1]:4d}")
    
    # Cross-validation score
    print("\nPerforming 5-fold cross-validation...")
    cv_scores = cross_val_score(model, X_train_combined, y_train, cv=5, scoring='accuracy')
    print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    return model, vectorizer


def save_model(model, vectorizer):
    """Save trained model and vectorizer"""
    print("\n" + "=" * 60)
    print("Saving Model")
    print("=" * 60)
    
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, 'email_model.pkl')
    vectorizer_path = os.path.join(models_dir, 'email_vectorizer.pkl')
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    
    print(f"Model saved to: {model_path}")
    print(f"Vectorizer saved to: {vectorizer_path}")
    
    # Save feature names for reference
    feature_names_path = os.path.join(models_dir, 'email_feature_names.pkl')
    feature_names = EmailFeatureExtractor.get_feature_names()
    with open(feature_names_path, 'wb') as f:
        pickle.dump(feature_names, f)
    print(f"Feature names saved to: {feature_names_path}")


def main():
    """Main training function"""
    print("\n" + "=" * 60)
    print("PhishShield Email Model Training")
    print("=" * 60)
    
    # Load datasets
    emails, labels, subjects = load_and_combine_datasets()
    
    # Extract features
    cleaned_emails, engineered_features = extract_combined_features(emails, subjects)
    
    # Train model
    model, vectorizer = train_model(cleaned_emails, engineered_features, labels)
    
    # Save model
    save_model(model, vectorizer)
    
    print("\n" + "=" * 60)
    print("Training Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
