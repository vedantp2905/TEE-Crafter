from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class GeoLocation(BaseModel):
    lat: float
    lon: float
    country_code: str

class Transaction(BaseModel):
    txn_id: str
    user_id: str
    amount: float
    currency: str
    timestamp: datetime
    merchant_category: str
    location: GeoLocation
    device_id: str

class FraudResult(BaseModel):
    txn_id: str
    risk_score: int
    is_blocked: bool
    triggered_rules: list[str]
