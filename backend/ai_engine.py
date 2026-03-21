import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime

class AIEngine:
    """AI-powered threat detection engine"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.model_trained = False
        self.model_path = 'models/threat_detector.pkl'
        self.scaler_path = 'models/scaler.pkl'
        
        # Feature names for consistency
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
        
        # Pattern learning storage
        self.learned_patterns = {}
        
        # Load existing model if available
        self.load_model()
        
        # If no model exists, initialize with default
        if not self.model_trained:
            self.initialize_default_model()
    
    def initialize_default_model(self):
        """Initialize a default pre-trained model"""
        print("Initializing default AI model...")
        
        # Create directory if it doesn't exist
        os.makedirs('models', exist_ok=True)
        
        # Initialize model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.scaler = StandardScaler()
        
        # Generate synthetic training data
        X_train, y_train = self.generate_synthetic_training_data()
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        self.model_trained = True
        
        # Save model
        self.save_model()
        
        print(f"Default model trained with {len(X_train)} samples")
        print(f"Model accuracy: {self.model.score(X_train_scaled, y_train) * 100:.2f}%")
    
    def generate_synthetic_training_data(self, n_samples=1000):
        """Generate synthetic training data for initial model"""
        X = []
        y = []
        
        # Generate attack samples (label = 1)
        for _ in range(n_samples // 2):
            features = {
                'endpoint_length': np.random.randint(10, 50),
                'pattern_length': np.random.randint(10, 100),
                'has_special_chars': np.random.choice([0, 1], p=[0.2, 0.8]),
                'has_sql_keywords': np.random.choice([0, 1], p=[0.3, 0.7]),
                'has_script_tags': np.random.choice([0, 1], p=[0.4, 0.6]),
                'has_path_traversal': np.random.choice([0, 1], p=[0.5, 0.5]),
                'method_post': np.random.choice([0, 1], p=[0.4, 0.6]),
                'method_delete': np.random.choice([0, 1], p=[0.7, 0.3]),
                'suspicious_endpoint': np.random.choice([0, 1], p=[0.3, 0.7])
            }
            X.append(list(features.values()))
            y.append(1)  # Attack
        
        # Generate normal samples (label = 0)
        for _ in range(n_samples // 2):
            features = {
                'endpoint_length': np.random.randint(5, 20),
                'pattern_length': np.random.randint(0, 30),
                'has_special_chars': np.random.choice([0, 1], p=[0.9, 0.1]),
                'has_sql_keywords': 0,
                'has_script_tags': 0,
                'has_path_traversal': 0,
                'method_post': np.random.choice([0, 1], p=[0.6, 0.4]),
                'method_delete': 0,
                'suspicious_endpoint': np.random.choice([0, 1], p=[0.9, 0.1])
            }
            X.append(list(features.values()))
            y.append(0)  # Normal
        
        return np.array(X), np.array(y)
    
    def predict(self, features):
        """Predict if request is a threat"""
        if not self.model_trained:
            # Fallback to rule-based detection
            return self.rule_based_detection(features)
        
        # Convert features dict to array
        feature_array = np.array([[features[name] for name in self.feature_names]])
        
        # Scale features
        feature_scaled = self.scaler.transform(feature_array)
        
        # Predict
        prediction = self.model.predict(feature_scaled)[0]
        confidence = self.model.predict_proba(feature_scaled)[0]
        
        return {
            'is_threat': bool(prediction),
            'confidence': float(confidence[1] if prediction else confidence[0])
        }
    
    def rule_based_detection(self, features):
        """Fallback rule-based threat detection"""
        threat_score = 0
        
        # Check for SQL injection indicators
        if features.get('has_sql_keywords', 0):
            threat_score += 0.4
        
        # Check for XSS indicators
        if features.get('has_script_tags', 0):
            threat_score += 0.4
        
        # Check for path traversal
        if features.get('has_path_traversal', 0):
            threat_score += 0.3
        
        # Check for suspicious endpoint
        if features.get('suspicious_endpoint', 0):
            threat_score += 0.2
        
        # Check for special characters
        if features.get('has_special_chars', 0):
            threat_score += 0.1
        
        is_threat = threat_score > 0.5
        
        return {
            'is_threat': is_threat,
            'confidence': min(threat_score, 1.0) if is_threat else 1.0 - threat_score
        }
    
    def learn_pattern(self, features, attack_type):
        """Learn from new attack patterns"""
        # Store pattern for future retraining
        if attack_type not in self.learned_patterns:
            self.learned_patterns[attack_type] = []
        
        self.learned_patterns[attack_type].append(features)
        
        # Retrain if we have enough new patterns
        total_patterns = sum(len(patterns) for patterns in self.learned_patterns.values())
        if total_patterns >= 100:  # Retrain every 100 new patterns
            self.retrain_model()
    
    def retrain_model(self):
        """Retrain the model with learned patterns"""
        if not self.learned_patterns:
            return
        
        print("Retraining AI model with new patterns...")
        
        # Prepare new training data
        X_new = []
        y_new = []
        
        for attack_type, patterns in self.learned_patterns.items():
            for pattern in patterns:
                X_new.append([pattern[name] for name in self.feature_names])
                y_new.append(1)  # All learned patterns are threats
        
        if len(X_new) == 0:
            return
        
        # Scale and train incrementally
        X_new_scaled = self.scaler.transform(np.array(X_new))
        
        # Partial fit (online learning)
        # Note: RandomForest doesn't support partial_fit, so we retrain
        # In production, consider using SGDClassifier or similar
        
        # For now, just update the model with new data
        self.model.fit(X_new_scaled, np.array(y_new))
        
        # Save updated model
        self.save_model()
        
        # Clear learned patterns
        self.learned_patterns = {}
        
        print(f"Model retrained with {len(X_new)} new patterns")
    
    def train_model(self):
        """Full model training (can be triggered manually)"""
        print("Starting full model training...")
        self.initialize_default_model()
    
    def save_model(self):
        """Save model and scaler to disk"""
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        print(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load model and scaler from disk"""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.model_trained = True
                print("Existing model loaded successfully")
            except Exception as e:
                print(f"Error loading model: {e}")
                self.model_trained = False
        else:
            print("No existing model found")
            self.model_trained = False
    
    def get_model_info(self):
        """Get information about the current model"""
        if not self.model_trained:
            return {
                'status': 'untrained',
                'message': 'Model not trained yet'
            }
        
        return {
            'status': 'trained',
            'n_estimators': self.model.n_estimators if hasattr(self.model, 'n_estimators') else 'N/A',
            'features': self.feature_names,
            'learned_patterns': len(self.learned_patterns)
        }
