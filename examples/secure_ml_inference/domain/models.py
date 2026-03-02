from pydantic import BaseModel, Field
from typing import List, Optional

class BrainScanFeature(BaseModel):
    region: str
    density_score: float
    anomaly_detected: bool

class PatientMetadata(BaseModel):
    patient_id: str
    age: int
    history_of_stroke: bool

class InferenceRequest(BaseModel):
    metadata: PatientMetadata
    scan_features: List[BrainScanFeature]

class InferenceResult(BaseModel):
    patient_id: str
    risk_score: float
    diagnosis_code: str
    confidence: float
    recommendation: str
