from schemas.transaction import Transaction, FraudResult
from .rules import FraudRulesEngine

def score_transaction(txn: Transaction, block_threshold: int = 80) -> FraudResult:
    engine = FraudRulesEngine()
    score = 0
    triggered = []

    if engine.check_blacklist(txn):
        score += 100
        triggered.append("DEVICE_BLACKLIST")

    if engine.check_geolocation(txn):
        score += 50
        triggered.append("HIGH_RISK_GEO")

    if engine.check_velocity(txn):
        score += 30
        triggered.append("HIGH_VELOCITY_AMOUNT")

    # Merchant Category logic
    if txn.merchant_category == "GAMBLING":
        score += 20
        triggered.append("HIGH_RISK_MCC")

    is_blocked = score >= block_threshold

    return FraudResult(
        txn_id=txn.txn_id,
        risk_score=score,
        is_blocked=is_blocked,
        triggered_rules=triggered
    )
