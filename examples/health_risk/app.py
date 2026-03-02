"""
Mock application consumed by Nitro-Agent.

Contract:
- Input:  a JSON string describing patient vitals.
- Output: a JSON string describing the computed risk score and bucket.

This file is what Phase 1 will conceptually wrap for vsock I/O.
"""

from io.serializers import parse_patient_vitals, result_to_json
from domain.logic import compute_risk


def process_patient_payload(payload: str) -> str:
    """Entry point used by the vsock wrapper.

    :param payload: JSON string representing patient vitals.
    :return: JSON string representing risk evaluation.
    """
    vitals = parse_patient_vitals(payload)
    result = compute_risk(vitals)
    return result_to_json(result)


if __name__ == "__main__":
    import sys

    data = sys.stdin.read()
    output = process_patient_payload(data)
    sys.stdout.write(output)
    sys.stdout.flush()
