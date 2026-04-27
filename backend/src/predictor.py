# predictor.py - Improved with confidence thresholding and filtering

import os
import joblib
import torch
import numpy as np
import warnings
# Filter specific sklearn warning about unpickling versions (1.7.2 -> 1.8.0)
from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

from lstm_model import LSTMModel

class Predictor:
    def __init__(self, models_dir, confidence_threshold=0.7):
        """
        Args:
            models_dir: Path to model artifacts
            confidence_threshold: Minimum confidence to report an attack (0.0-1.0)
                                 Higher = fewer false positives, might miss some attacks
                                 Lower = more detections, more false positives
                                 Recommended: 0.7-0.85 for production
        """
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.confidence_threshold = confidence_threshold
        
        # Load artifacts
        self.scaler = joblib.load(os.path.join(models_dir, "scaler.pkl"))
        self.label_encoder = joblib.load(os.path.join(models_dir, "label_encoder.pkl"))
        
        # Load model
        input_dim = self.scaler.n_features_in_
        num_classes = len(self.label_encoder.classes_)
        
        self.model = LSTMModel(
            input_dim=input_dim,
            hidden_dim=64,
            num_layers=2,
            num_classes=num_classes
        ).to(self.device)
        
        model_path = os.path.join(models_dir, "lstm_cicids.pth")
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.eval()
        
        print(f"[OK] Model loaded: {num_classes} classes, {input_dim} features")
        print(f"[*]  Confidence threshold: {confidence_threshold:.2f}")
    
    def predict_df(self, df):
        """Original method - returns only labels"""
        results = self.predict_df_with_scores(df)
        return [label for label, _ in results]
    
    def predict_df_with_scores(self, df, seq_len=5):
        """
        Predict with confidence filtering
        
        Args:
            df: DataFrame with features
            seq_len: Sequence length for LSTM
            
        Returns:
            List of (label, score) tuples, filtered by confidence threshold
        """
        if df.empty or len(df) < seq_len:
            print(f"[!] Not enough data: {len(df)} rows (need {seq_len})")
            return []
        
        try:
            # Get numeric columns only
            numeric_df = df.select_dtypes(include=[np.number])
            
            # Scale features
            X_scaled = self.scaler.transform(numeric_df.values)
            
            # Build sequences
            sequences = []
            for i in range(len(X_scaled) - seq_len + 1):
                seq = X_scaled[i:i+seq_len]
                sequences.append(seq)
            
            if len(sequences) == 0:
                return []
            
            # Convert to tensor
            X_tensor = torch.tensor(
                np.array(sequences),
                dtype=torch.float32
            ).to(self.device)
            
            # Predict
            with torch.no_grad():
                logits = self.model(X_tensor)
                probs = torch.softmax(logits, dim=1)
                confidences, pred_indices = torch.max(probs, dim=1)
                
                pred_indices = pred_indices.cpu().numpy()
                confidences = confidences.cpu().numpy()
            
            # Decode labels
            labels = self.label_encoder.inverse_transform(pred_indices)
            
            # Apply intelligent filtering
            results = []
            for label, score in zip(labels, confidences):
                # Always include BENIGN (regardless of threshold)
                if label.upper() == "BENIGN":
                    results.append((label, float(score)))
                # For attacks, apply confidence threshold
                elif score >= self.confidence_threshold:
                    results.append((label, float(score)))
                # If below threshold, classify as BENIGN instead
                else:
                    results.append(("BENIGN", float(score)))
            
            # Count filtered predictions
            filtered_count = sum(1 for label, score in zip(labels, confidences) 
                               if label.upper() != "BENIGN" and score < self.confidence_threshold)
            
            if filtered_count > 0:
                print(f"   [~] Filtered {filtered_count} low-confidence predictions (< {self.confidence_threshold:.2f})")
            
            print(f"[OK] Predicted {len(results)} sequences")
            return results
            
        except Exception as e:
            print(f"[!] Prediction error: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def set_confidence_threshold(self, threshold):
        """Update confidence threshold dynamically"""
        if not 0 <= threshold <= 1:
            raise ValueError("Threshold must be between 0 and 1")
        
        old_threshold = self.confidence_threshold
        self.confidence_threshold = threshold
        print(f"[*] Confidence threshold updated: {old_threshold:.2f} -> {threshold:.2f}")
    
    def get_prediction_stats(self, results):
        """Get statistics about predictions"""
        if not results:
            return {}
        
        total = len(results)
        benign = sum(1 for label, _ in results if label.upper() == "BENIGN")
        malicious = total - benign
        
        # Average confidence by type
        benign_scores = [score for label, score in results if label.upper() == "BENIGN"]
        malicious_scores = [score for label, score in results if label.upper() != "BENIGN"]
        
        stats = {
            "total": total,
            "benign": benign,
            "malicious": malicious,
            "avg_benign_confidence": np.mean(benign_scores) if benign_scores else 0,
            "avg_malicious_confidence": np.mean(malicious_scores) if malicious_scores else 0
        }
        
        return stats