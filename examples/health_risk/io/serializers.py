import json
from typing import Any
from domain.models import PatientVitals, RiskResult


def parse_patient_vitals(payload: str) -> PatientVitals:
    data: Any = json.loads(payload)
    return PatientVitals(**data)


def result_to_json(result: RiskResult) -> str:
    return result.model_dump_json()
