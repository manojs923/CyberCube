import os
import joblib
import numpy as np
import pandas as pd
import shap

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(PROJECT_ROOT, 'ml', 'model.pkl')

class XAIExplainerService:
    def __init__(self):
        self.pipeline = None
        self.scaler = None
        self.classifier = None
        self.explainer = None
        self.features = []
        self.classes = []
        self._load_model()

    def _load_model(self):
        if not os.path.exists(MODEL_PATH):
            print(f"Warning: Model not found at {MODEL_PATH}")
            return
            
        try:
            self.pipeline = joblib.load(MODEL_PATH)
            self.scaler = self.pipeline.named_steps['scaler']
            self.classifier = self.pipeline.named_steps['classifier']
            self.features = list(self.pipeline.feature_names_in_)
            self.classes = list(self.pipeline.classes_)
            
            # Initialize SHAP TreeExplainer for the Random Forest ensemble
            self.explainer = shap.TreeExplainer(self.classifier)
            print("SHAP TreeExplainer successfully initialized.")
        except Exception as e:
            print(f"Failed to initialize SHAP TreeExplainer: {e}")

    def explain_threat_features(self, feature_dict: dict, predicted_class: str = None):
        """
        Compute local SHAP feature attributions for a single threat incident.
        Returns the top contributing features and directional weights.
        """
        if not self.explainer or not self.pipeline:
            self._load_model()
            if not self.explainer:
                return {"error": "XAI Explainer unavailable"}

        # Construct single-row DataFrame aligned with trained features
        row = {}
        for feat in self.features:
            val = feature_dict.get(feat, 0.0)
            try:
                row[feat] = float(val) if val is not None else 0.0
            except (ValueError, TypeError):
                row[feat] = 0.0

        df_row = pd.DataFrame([row])[self.features]
        scaled_row = self.scaler.transform(df_row)

        # Run SHAP computation
        shap_values = self.explainer.shap_values(scaled_row)

        # Find target class index
        if not predicted_class or predicted_class not in self.classes:
            preds = self.pipeline.predict(df_row)
            target_class = preds[0]
        else:
            target_class = predicted_class

        target_idx = self.classes.index(target_class)

        # Handle different SHAP output formats (3D ndarray vs list of 2D ndarrays)
        if isinstance(shap_values, np.ndarray) and len(shap_values.shape) == 3:
            class_shap = shap_values[0, :, target_idx]
        elif isinstance(shap_values, list):
            class_shap = shap_values[target_idx][0]
        else:
            class_shap = np.array(shap_values)[0]

        # Pair each feature with its SHAP contribution and actual value
        feature_attributions = []
        for i, feat in enumerate(self.features):
            impact = float(class_shap[i])
            actual_val = row[feat]
            feature_attributions.append({
                "feature": feat,
                "value": round(actual_val, 2),
                "shap_value": round(impact, 4),
                "abs_impact": abs(impact),
                "direction": "positive" if impact >= 0 else "negative"
            })

        # Sort by absolute impact descending
        feature_attributions.sort(key=lambda x: x["abs_impact"], reverse=True)

        # Top 8 most influential features for visualization
        top_attributions = feature_attributions[:8]

        return {
            "target_class": target_class,
            "classes": self.classes,
            "top_features": top_attributions,
            "summary": f"Top influential factors driving '{target_class}' classification: " + 
                       ", ".join([f"{item['feature']} (SHAP: {item['shap_value']:+.3f})" for item in top_attributions[:3]])
        }

    def counterfactual_analysis(self, feature_dict: dict, perturbed_features: dict = None):
        """
        Simulate counterfactual "What-If" perturbations on flow features.
        Calculates baseline vs perturbed prediction classes and confidence deltas.
        """
        if not self.pipeline:
            self._load_model()
            if not self.pipeline:
                return {"error": "Model pipeline unavailable"}

        # Baseline vector
        baseline_row = {}
        for feat in self.features:
            val = feature_dict.get(feat, 0.0)
            try:
                baseline_row[feat] = float(val) if val is not None else 0.0
            except (ValueError, TypeError):
                baseline_row[feat] = 0.0

        df_baseline = pd.DataFrame([baseline_row])[self.features]
        base_probs = self.pipeline.predict_proba(df_baseline)[0]
        base_pred = self.pipeline.predict(df_baseline)[0]
        base_conf = float(base_probs[self.classes.index(base_pred)])

        # Perturbed vector
        perturbed_row = dict(baseline_row)
        if perturbed_features:
            for feat, new_val in perturbed_features.items():
                if feat in self.features:
                    try:
                        perturbed_row[feat] = float(new_val)
                    except (ValueError, TypeError):
                        pass

        df_perturbed = pd.DataFrame([perturbed_row])[self.features]
        pert_probs = self.pipeline.predict_proba(df_perturbed)[0]
        pert_pred = self.pipeline.predict(df_perturbed)[0]
        pert_conf = float(pert_probs[self.classes.index(pert_pred)])

        # Class shift probabilities
        probability_comparison = []
        for idx, cls_name in enumerate(self.classes):
            orig_p = float(base_probs[idx])
            new_p = float(pert_probs[idx])
            probability_comparison.append({
                "class_name": cls_name,
                "original_probability": round(orig_p, 4),
                "perturbed_probability": round(new_p, 4),
                "delta": round(new_p - orig_p, 4)
            })

        return {
            "baseline": {
                "predicted_class": base_pred,
                "confidence": round(base_conf, 4)
            },
            "counterfactual": {
                "predicted_class": pert_pred,
                "confidence": round(pert_conf, 4)
            },
            "decision_changed": (base_pred != pert_pred),
            "class_probabilities": probability_comparison,
            "applied_perturbations": perturbed_features or {}
        }

# Global singleton
xai_service = XAIExplainerService()
