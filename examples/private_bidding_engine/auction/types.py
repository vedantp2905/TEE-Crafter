from dataclasses import dataclass
from typing import List, Dict, Optional
from pydantic import BaseModel

class Bid(BaseModel):
    bidder_id: str
    auction_id: str
    amount: float
    currency: str
    is_sealed: bool = True

class AuctionResult(BaseModel):
    auction_id: str
    winner_id: Optional[str]
    winning_amount: float
    total_bids: int
    second_price: Optional[float] # Vickrey auction style
