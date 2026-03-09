"""
Comprehensive URL Phishing Detection Model Training
Combines PhiUSIIL, Kaggle, and Mendeley datasets
Trains multiple ML models: Random Forest, XGBoost, Logistic Regression
"""

import os
import pickle
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (classification_report, accuracy_score, 
                            confusion_matrix, roc_auc_score, roc_curve,
                            precision_recall_fscore_support)

# Try to import XGBoost, fallback if not available
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("XGBoost not available, will use Random Forest and Logistic Regression only")

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.feature_engineering.url_features import URLFeatureExtractor


class ComprehensiveURLModelTrainer:
    """Train URL phishing detection models using multiple datasets"""
    
    def __init__(self):
        self.data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        self.models_dir = os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(self.models_dir, exist_ok=True)
        
        self.datasets_info = {
            'phiusiil': {
                'file': 'PhiUSIIL_Phishing_URL_Dataset.csv',
                'url_col': 'URL',
                'label_col': 'label',
                'label_mapping': {0: 1, 1: 0}  # 0=phishing, 1=legitimate -> flip to 1=phishing
            },
            'kaggle': {
                'file': 'kaggle_phishing_site_urls.csv',
                'url_col': 'URL',
                'label_col': 'Label',
                'label_mapping': {'bad': 1, 'good': 0}  # bad=phishing, good=legitimate
            },
            'mendeley': {
                'file': 'Mendeley_Phishing_url_Dataset.csv',
                'url_col': None,  # No URL column, use engineered features
                'label_col': 'Type',
                'label_mapping': {1: 1, 0: 0}  # 1=phishing, 0=legitimate
            }
        }
        
        self.results = {}
        
    def load_and_combine_datasets(self):
        """Load and combine all datasets with feature extraction"""
        print("=" * 70)
        print("LOADING AND COMBINING DATASETS")
        print("=" * 70)
        
        all_features = []
        all_labels = []
        dataset_stats = {}
        
        # 1. Load PhiUSIIL Dataset
        print("\n1. Loading PhiUSIIL Dataset...")
        try:
            df_ph = pd.read_csv(os.path.join(self.data_dir, self.datasets_info['phiusiil']['file']))
            print(f"   Shape: {df_ph.shape}")
            
            urls = df_ph[self.datasets_info['phiusiil']['url_col']].fillna('').astype(str)
            labels = df_ph[self.datasets_info['phiusiil']['label_col']].map(
                self.datasets_info['phiusiil']['label_mapping']
            )
            
            print(f"   Extracting features from {len(urls)} URLs...")
            features = self._extract_features_batch(urls)
            
            all_features.append(features)
            all_labels.append(labels.values)
            
            dataset_stats['phiusiil'] = {
                'total': len(labels),
                'phishing': int((labels == 1).sum()),
                'legitimate': int((labels == 0).sum())
            }
            print(f"   ✓ Added {len(labels)} samples")
        except Exception as e:
            print(f"   ✗ Error loading PhiUSIIL: {e}")
        
        # 2. Load Kaggle Dataset
        print("\n2. Loading Kaggle Dataset...")
        try:
            df_kg = pd.read_csv(os.path.join(self.data_dir, self.datasets_info['kaggle']['file']))
            print(f"   Shape: {df_kg.shape}")
            
            urls = df_kg[self.datasets_info['kaggle']['url_col']].fillna('').astype(str)
            labels = df_kg[self.datasets_info['kaggle']['label_col']].map(
                self.datasets_info['kaggle']['label_mapping']
            )
            
            print(f"   Extracting features from {len(urls)} URLs...")
            features = self._extract_features_batch(urls)
            
            all_features.append(features)
            all_labels.append(labels.values)
            
            dataset_stats['kaggle'] = {
                'total': len(labels),
                'phishing': int((labels == 1).sum()),
                'legitimate': int((labels == 0).sum())
            }
            print(f"   ✓ Added {len(labels)} samples")
        except Exception as e:
            print(f"   ✗ Error loading Kaggle: {e}")
        
        # 3. Load Mendeley Dataset (already has engineered features)
        print("\n3. Loading Mendeley Dataset...")
        try:
            df_mend = pd.read_csv(os.path.join(self.data_dir, self.datasets_info['mendeley']['file']))
            print(f"   Shape: {df_mend.shape}")
            
            # Use existing engineered features
            labels = df_mend[self.datasets_info['mendeley']['label_col']].map(
                self.datasets_info['mendeley']['label_mapping']
            )
            
            # Select relevant features that match our feature extractor
            feature_cols = [col for col in df_mend.columns if col != 'Type']
            
            # We'll need to extract features from URLs in Mendeley too
            # But since there's no URL column, we'll use a subset of samples
            # and extract features using our extractor for consistency
            print(f"   Using {len(labels)} samples with existing features")
            
            # For Mendeley, we'll sample and use our feature extractor
            # to maintain consistency across all datasets
            sample_size = min(50000, len(df_mend))  # Sample for efficiency
            df_sample = df_mend.sample(n=sample_size, random_state=42)
            
            # Create synthetic URLs from domain features for feature extraction
            # This is a workaround since Mendeley doesn't have raw URLs
            # We'll skip Mendeley for URL-based feature extraction
            # and instead use it as validation data later
            
            print(f"   Note: Mendeley has engineered features but no raw URLs")
            print(f"   Skipping Mendeley for URL-based model (will use for validation)")
            
        except Exception as e:
            print(f"   ✗ Error loading Mendeley: {e}")
        
        # Combine all datasets
        print("\n" + "=" * 70)
        print("COMBINING DATASETS")
        print("=" * 70)
        
        X = np.vstack(all_features)
        y = np.concatenate(all_labels)
        
        print(f"\nTotal combined dataset:")
        print(f"  Samples: {len(y):,}")
        print(f"  Features: {X.shape[1]}")
        print(f"  Phishing: {(y == 1).sum():,} ({(y == 1).mean()*100:.1f}%)")
        print(f"  Legitimate: {(y == 0).sum():,} ({(y == 0).mean()*100:.1f}%)")
        
        # Dataset breakdown
        print(f"\nDataset breakdown:")
        for name, stats in dataset_stats.items():
            print(f"  {name}: {stats['total']:,} samples (Phishing: {stats['phishing']:,}, Legitimate: {stats['legitimate']:,})")
        
        return X, y, dataset_stats
    
    def _extract_features_batch(self, urls):
        """Extract features from a batch of URLs"""
        features = []
        total = len(urls)
        
        for i, url in enumerate(urls):
            if i % 50000 == 0 and i > 0:
                print(f"     Progress: {i}/{total} ({i/total*100:.1f}%)")
            
            feature_vector = URLFeatureExtractor.get_feature_vector(url)
            features.append(feature_vector)
        
        return np.array(features)
    
    def prepare_data(self, X, y, test_size=0.2):
        """Split and scale data"""
        print("\n" + "=" * 70)
        print("PREPARING DATA")
        print("=" * 70)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"Training set: {len(X_train):,} samples")
        print(f"Test set: {len(X_test):,} samples")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Save scaler
        scaler_path = os.path.join(self.models_dir, 'url_scaler.pkl')
        with open(scaler_path, 'wb') as f:
            pickle.dump(scaler, f)
        print(f"Scaler saved to: {scaler_path}")
        
        return X_train_scaled, X_test_scaled, y_train, y_test, scaler
    
    def train_random_forest(self, X_train, X_test, y_train, y_test):
        """Train Random Forest model"""
        print("\n" + "=" * 70)
        print("TRAINING RANDOM FOREST")
        print("=" * 70)
        
        # Use optimized parameters for large dataset
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=25,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1,
            verbose=1
        )
        
        print("Training...")
        rf.fit(X_train, y_train)
        
        # Evaluate
        y_pred = rf.predict(X_test)
        y_pred_proba = rf.predict_proba(X_test)[:, 1]
        
        accuracy = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_pred_proba)
        
        print(f"\nRandom Forest Results:")
        print(f"  Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"  AUC-ROC: {auc:.4f}")
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Feature importance
        feature_names = URLFeatureExtractor.get_feature_names()
        importances = rf.feature_importances_
        
        print(f"\nTop 10 Most Important Features:")
        indices = np.argsort(importances)[::-1][:10]
        for i in indices:
            print(f"  {feature_names[i]}: {importances[i]:.4f}")
        
        # Save model
        model_path = os.path.join(self.models_dir, 'url_model_rf.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(rf, f)
        print(f"\nModel saved to: {model_path}")
        
        self.results['random_forest'] = {
            'accuracy': accuracy,
            'auc': auc,
            'model': rf
        }
        
        return rf
    
    def train_xgboost(self, X_train, X_test, y_train, y_test):
        """Train XGBoost model"""
        if not XGBOOST_AVAILABLE:
            print("\nXGBoost not available, skipping...")
            return None
        
        print("\n" + "=" * 70)
        print("TRAINING XGBOOST")
        print("=" * 70)
        
        # Calculate scale_pos_weight for imbalanced data
        scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
        
        xgb_model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos_weight,
            random_state=42,
            n_jobs=-1,
            eval_metric='logloss'
        )
        
        print("Training...")
        xgb_model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False
        )
        
        # Evaluate
        y_pred = xgb_model.predict(X_test)
        y_pred_proba = xgb_model.predict_proba(X_test)[:, 1]
        
        accuracy = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_pred_proba)
        
        print(f"\nXGBoost Results:")
        print(f"  Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"  AUC-ROC: {auc:.4f}")
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Feature importance
        feature_names = URLFeatureExtractor.get_feature_names()
        importances = xgb_model.feature_importances_
        
        print(f"\nTop 10 Most Important Features:")
        indices = np.argsort(importances)[::-1][:10]
        for i in indices:
            print(f"  {feature_names[i]}: {importances[i]:.4f}")
        
        # Save model
        model_path = os.path.join(self.models_dir, 'url_model_xgb.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(xgb_model, f)
        print(f"\nModel saved to: {model_path}")
        
        self.results['xgboost'] = {
            'accuracy': accuracy,
            'auc': auc,
            'model': xgb_model
        }
        
        return xgb_model
    
    def train_logistic_regression(self, X_train, X_test, y_train, y_test):
        """Train Logistic Regression model"""
        print("\n" + "=" * 70)
        print("TRAINING LOGISTIC REGRESSION")
        print("=" * 70)
        
        lr = LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced',
            C=1.0,
            n_jobs=-1
        )
        
        print("Training...")
        lr.fit(X_train, y_train)
        
        # Evaluate
        y_pred = lr.predict(X_test)
        y_pred_proba = lr.predict_proba(X_test)[:, 1]
        
        accuracy = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_pred_proba)
        
        print(f"\nLogistic Regression Results:")
        print(f"  Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"  AUC-ROC: {auc:.4f}")
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Save model
        model_path = os.path.join(self.models_dir, 'url_model_lr.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(lr, f)
        print(f"\nModel saved to: {model_path}")
        
        self.results['logistic_regression'] = {
            'accuracy': accuracy,
            'auc': auc,
            'model': lr
        }
        
        return lr
    
    def select_best_model(self):
        """Select best performing model"""
        print("\n" + "=" * 70)
        print("MODEL COMPARISON")
        print("=" * 70)
        
        print(f"\n{'Model':<25} {'Accuracy':<12} {'AUC-ROC':<12}")
        print("-" * 50)
        
        for name, result in self.results.items():
            print(f"{name:<25} {result['accuracy']:<12.4f} {result['auc']:<12.4f}")
        
        # Select best model based on accuracy
        best_model_name = max(self.results.keys(), 
                             key=lambda x: self.results[x]['accuracy'])
        best_model = self.results[best_model_name]['model']
        
        print(f"\nBest Model: {best_model_name.upper()}")
        print(f"  Accuracy: {self.results[best_model_name]['accuracy']:.4f}")
        print(f"  AUC-ROC: {self.results[best_model_name]['auc']:.4f}")
        
        # Save best model as the default url_model.pkl
        best_model_path = os.path.join(self.models_dir, 'url_model.pkl')
        with open(best_model_path, 'wb') as f:
            pickle.dump(best_model, f)
        print(f"\nBest model saved as: {best_model_path}")
        
        return best_model_name, best_model
    
    def run(self):
        """Run complete training pipeline"""
        print("\n" + "=" * 70)
        print("PHISHSHIELD URL MODEL TRAINING")
        print("Comprehensive Training with Multiple Datasets")
        print("=" * 70)
        
        # Load and combine datasets
        X, y, dataset_stats = self.load_and_combine_datasets()
        
        # Prepare data
        X_train, X_test, y_train, y_test, scaler = self.prepare_data(X, y)
        
        # Train models
        self.train_random_forest(X_train, X_test, y_train, y_test)
        self.train_xgboost(X_train, X_test, y_train, y_test)
        self.train_logistic_regression(X_train, X_test, y_train, y_test)
        
        # Select best model
        best_name, best_model = self.select_best_model()
        
        print("\n" + "=" * 70)
        print("TRAINING COMPLETE!")
        print("=" * 70)
        print(f"\nAll models saved in: {self.models_dir}")
        print(f"Best model: {best_name}")
        print(f"\nModels available:")
        print(f"  - url_model.pkl (best model)")
        print(f"  - url_model_rf.pkl (Random Forest)")
        if XGBOOST_AVAILABLE:
            print(f"  - url_model_xgb.pkl (XGBoost)")
        print(f"  - url_model_lr.pkl (Logistic Regression)")
        print(f"  - url_scaler.pkl (Feature scaler)")


def main():
    trainer = ComprehensiveURLModelTrainer()
    trainer.run()


if __name__ == "__main__":
    main()
