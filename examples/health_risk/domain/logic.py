import numpy as np
from .models import PatientVitals, RiskResult


def _bp_component(v: PatientVitals) -> float:
    systolic_excess = max(0, v.blood_pressure_systolic - 130)
    diastolic_excess = max(0, v.blood_pressure_diastolic - 85)
    return (systolic_excess * 0.15) + (diastolic_excess * 0.1)


def _cholesterol_component(v: PatientVitals) -> float:
    ldl_term = max(0, v.cholesterol_ldl - 130) * 0.12
    hdl_term = max(0, 50 - v.cholesterol_hdl) * 0.18
    return ldl_term + hdl_term


def _lifestyle_component(v: PatientVitals) -> float:
    base = 0.0
    if v.smoker:
        base += 15.0
    if v.diabetic:
        base += 20.0
    age_penalty = max(0, v.age - 50) * 0.6
    return base + age_penalty


def compute_risk(vitals: PatientVitals) -> RiskResult:
    components = np.array([
        _bp_component(vitals),
        _cholesterol_component(vitals),
        _lifestyle_component(vitals),
    ])
    raw_score = float(components.sum())

    if raw_score < 25:
        bucket = "LOW"
        explanation = "Overall cardiovascular risk appears low."
    elif raw_score < 55:
        bucket = "MEDIUM"
        explanation = "Some risk factors present; consider lifestyle changes."
    else:
        bucket = "HIGH"
        explanation = "Multiple elevated risk factors; intervention recommended."

    return RiskResult(
        patient_id=vitals.patient_id,
        risk_score=round(raw_score, 2),
        risk_bucket=bucket,
        explanation=explanation,
    )
