from typing import List
from .models import InferenceRequest, InferenceResult

class BrainHealthModel:
    def __init__(self):
        # Simulate loading model weights
        self.base_risk = 0.1

    def predict(self, request: InferenceRequest) -> InferenceResult:
        risk_score = self.base_risk
        
        # Age factor
        if request.metadata.age > 60:
            risk_score += 0.2
        
        # History factor
        if request.metadata.history_of_stroke:
            risk_score += 0.3
            
        # Feature analysis
        anomaly_count = 0
        max_density = 0.0
        
        for feature in request.scan_features:
            if feature.anomaly_detected:
                anomaly_count += 1
                risk_score += 0.15
            max_density = max(max_density, feature.density_score)
            
        if max_density > 0.8:
            risk_score += 0.1
            
        # Cap risk
        risk_score = min(0.99, risk_score)
        
        # Diagnosis Logic
        if risk_score > 0.7:
            code = "CRITICAL_ATTENTION"
            rec = "Immediate neurologial intervention required."
        elif risk_score > 0.4:
            code = "MONITOR"
            rec = "Schedule follow-up scan in 3 months."
        else:
            code = "NORMAL"
            rec = "Routine annual checkup."
            
        return InferenceResult(
            patient_id=request.metadata.patient_id,
            risk_score=round(risk_score, 4),
            diagnosis_code=code,
            confidence=0.92, # Simulated model confidence
            recommendation=rec
        )
