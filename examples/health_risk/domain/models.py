from pydantic import BaseModel, Field


class PatientVitals(BaseModel):
    patient_id: str
    age: int = Field(ge=0, le=120)
    blood_pressure_systolic: int
    blood_pressure_diastolic: int
    heart_rate: int
    cholesterol_ldl: float
    cholesterol_hdl: float
    smoker: bool
    diabetic: bool


class RiskResult(BaseModel):
    patient_id: str
    risk_score: float
    risk_bucket: str
    explanation: str
