#!/usr/bin/env python3
"""
AI Model Training Script for Healthcare Security System

This script trains a machine learning model to detect cyber attacks
based on historical attack patterns and features.

Usage:
    python train_model.py [--data DATA_FILE] [--output MODEL_FILE]
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import argparse
import os
from datetime import datetime

class ThreatDetectorTrainer:
    """Train and evaluate threat detection models"""
    
    def __init__(self):
        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                random_state=42
            )
        }
        self.best_model = None
        self.scaler = StandardScaler()
        
        self.feature_names = [
            'endpoint_length',
            'pattern_length',
            'has_special_chars',
            'has_sql_keywords',
            'has_script_tags',
            'has_path_traversal',
            'method_post',
            'method_delete',
            'suspicious_endpoint'
        ]
    
    def generate_training_data(self, n_samples=5000):
        """Generate synthetic training data with realistic attack patterns"""
        print(f"Generating {n_samples} training samples...")
        
        X = []
        y = []
        attack_types = []
        
        # Attack samples (50% of data)
        n_attacks = n_samples // 2
        
        # SQL Injection attacks (25% of attacks)
        for _ in range(n_attacks // 4):
            features = {
                'endpoint_length': np.random.randint(15, 60),
                'pattern_length': np.random.randint(20, 150),
                'has_special_chars': 1,
                'has_sql_keywords': np.random.choice([0, 1], p=[0.1, 0.9]),
                'has_script_tags': 0,
                'has_path_traversal': 0,
                'method_post': np.random.choice([0, 1], p=[0.3, 0.7]),
                'method_delete': 0,
                'suspicious_endpoint': np.random.choice([0, 1], p=[0.4, 0.6])
            }
            X.append(list(features.values()))
            y.append(1)
            attack_types.append('sql_injection')
        
        # XSS attacks (25% of attacks)
        for _ in range(n_attacks // 4):
            features = {
                'endpoint_length': np.random.randint(10, 40),
                'pattern_length': np.random.randint(30, 200),
                'has_special_chars': 1,
                'has_sql_keywords': 0,
                'has_script_tags': np.random.choice([0, 1], p=[0.1, 0.9]),
                'has_path_traversal': 0,
                'method_post': np.random.choice([0, 1], p=[0.4, 0.6]),
                'method_delete': 0,
                'suspicious_endpoint': np.random.choice([0, 1], p=[0.6, 0.4])
            }
            X.append(list(features.values()))
            y.append(1)
            attack_types.append('xss')
        
        # Path Traversal attacks (25% of attacks)
        for _ in range(n_attacks // 4):
            features = {
                'endpoint_length': np.random.randint(20, 80),
                'pattern_length': np.random.randint(15, 100),
                'has_special_chars': 1,
                'has_sql_keywords': 0,
                'has_script_tags': 0,
                'has_path_traversal': np.random.choice([0, 1], p=[0.1, 0.9]),
                'method_post': 0,
                'method_delete': 0,
                'suspicious_endpoint': np.random.choice([0, 1], p=[0.3, 0.7])
            }
            X.append(list(features.values()))
            y.append(1)
            attack_types.append('path_traversal')
        
        # Command Injection attacks (25% of attacks)
        for _ in range(n_attacks // 4):
            features = {
                'endpoint_length': np.random.randint(15, 50),
                'pattern_length': np.random.randint(10, 80),
                'has_special_chars': np.random.choice([0, 1], p=[0.1, 0.9]),
                'has_sql_keywords': 0,
                'has_script_tags': 0,
                'has_path_traversal': np.random.choice([0, 1], p=[0.6, 0.4]),
                'method_post': np.random.choice([0, 1], p=[0.4, 0.6]),
                'method_delete': np.random.choice([0, 1], p=[0.7, 0.3]),
                'suspicious_endpoint': np.random.choice([0, 1], p=[0.2, 0.8])
            }
            X.append(list(features.values()))
            y.append(1)
            attack_types.append('command_injection')
        
        # Normal traffic samples (50% of data)
        n_normal = n_samples - n_attacks
        for _ in range(n_normal):
            features = {
                'endpoint_length': np.random.randint(5, 25),
                'pattern_length': np.random.randint(0, 40),
                'has_special_chars': np.random.choice([0, 1], p=[0.95, 0.05]),
                'has_sql_keywords': 0,
                'has_script_tags': 0,
                'has_path_traversal': 0,
                'method_post': np.random.choice([0, 1], p=[0.6, 0.4]),
                'method_delete': 0,
                'suspicious_endpoint': np.random.choice([0, 1], p=[0.95, 0.05])
            }
            X.append(list(features.values()))
            y.append(0)
            attack_types.append('normal')
        
        return np.array(X), np.array(y), attack_types
    
    def load_data_from_csv(self, filepath):
        """Load training data from CSV file"""
        print(f"Loading data from {filepath}...")
        
        df = pd.read_csv(filepath)
        
        # Extract features and labels
        X = df[self.feature_names].values
        y = df['is_threat'].values
        
        return X, y
    
    def train(self, X, y, model_name='random_forest'):
        """Train the model"""
        print(f"\nTraining {model_name} model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        model = self.models[model_name]
        model.fit(X_train_scaled, y_train)
        
        # Evaluate
        train_score = model.score(X_train_scaled, y_train)
        test_score = model.score(X_test_scaled, y_test)
        
        print(f"Training accuracy: {train_score * 100:.2f}%")
        print(f"Test accuracy: {test_score * 100:.2f}%")
        
        # Cross-validation
        cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)
        print(f"Cross-validation accuracy: {cv_scores.mean() * 100:.2f}% (+/- {cv_scores.std() * 100:.2f}%)")
        
        # Detailed metrics
        y_pred = model.predict(X_test_scaled)
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Threat']))
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        # ROC AUC
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(X_test_scaled)[:, 1]
            roc_auc = roc_auc_score(y_test, y_proba)
            print(f"\nROC AUC Score: {roc_auc:.4f}")
        
        # Feature importance
        if hasattr(model, 'feature_importances_'):
            print("\nFeature Importances:")
            for name, importance in zip(self.feature_names, model.feature_importances_):
                print(f"  {name}: {importance:.4f}")
        
        self.best_model = model
        return model, test_score
    
    def compare_models(self, X, y):
        """Compare different models and select the best one"""
        print("\n" + "="*50)
        print("Comparing Models")
        print("="*50)
        
        results = {}
        
        for model_name in self.models.keys():
            model, score = self.train(X, y, model_name)
            results[model_name] = score
            print("\n" + "-"*50 + "\n")
        
        # Select best model
        best_name = max(results, key=results.get)
        print(f"\nBest model: {best_name} (Accuracy: {results[best_name] * 100:.2f}%)")
        
        return best_name
    
    def save_model(self, model_dir='models'):
        """Save the trained model and scaler"""
        os.makedirs(model_dir, exist_ok=True)
        
        model_path = os.path.join(model_dir, 'threat_detector.pkl')
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        
        joblib.dump(self.best_model, model_path)
        joblib.dump(self.scaler, scaler_path)
        
        print(f"\nModel saved to {model_path}")
        print(f"Scaler saved to {scaler_path}")
        
        # Save metadata
        metadata = {
            'trained_date': datetime.now().isoformat(),
            'feature_names': self.feature_names,
            'model_type': type(self.best_model).__name__
        }
        
        metadata_path = os.path.join(model_dir, 'metadata.json')
        import json
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Metadata saved to {metadata_path}")

def main():
    parser = argparse.ArgumentParser(description='Train AI threat detection model')
    parser.add_argument('--data', type=str, help='Path to training data CSV file')
    parser.add_argument('--samples', type=int, default=5000, help='Number of synthetic samples to generate')
    parser.add_argument('--model', type=str, default='compare', 
                       choices=['random_forest', 'gradient_boosting', 'compare'],
                       help='Model to train (or compare all)')
    parser.add_argument('--output', type=str, default='models', help='Output directory for model files')
    
    args = parser.parse_args()
    
    print("="*50)
    print("Healthcare Security System - AI Model Training")
    print("="*50)
    
    trainer = ThreatDetectorTrainer()
    
    # Load or generate data
    if args.data and os.path.exists(args.data):
        X, y = trainer.load_data_from_csv(args.data)
    else:
        X, y, attack_types = trainer.generate_training_data(args.samples)
        
        # Save generated data for reference
        os.makedirs('data', exist_ok=True)
        df = pd.DataFrame(X, columns=trainer.feature_names)
        df['is_threat'] = y
        df.to_csv('data/generated_training_data.csv', index=False)
        print(f"Generated training data saved to data/generated_training_data.csv")
    
    # Train model(s)
    if args.model == 'compare':
        best_model_name = trainer.compare_models(X, y)
    else:
        trainer.train(X, y, args.model)
    
    # Save model
    trainer.save_model(args.output)
    
    print("\n" + "="*50)
    print("Training completed successfully!")
    print("="*50)

if __name__ == '__main__':
    main()
