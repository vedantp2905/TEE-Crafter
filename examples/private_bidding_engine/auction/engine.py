from typing import List
from .types import Bid, AuctionResult

class VickreyAuctionEngine:
    def process_auction(self, auction_id: str, bids: List[Bid]) -> AuctionResult:
        # Filter bids for this auction
        valid_bids = [b for b in bids if b.auction_id == auction_id]
        
        if not valid_bids:
            return AuctionResult(
                auction_id=auction_id,
                winner_id=None,
                winning_amount=0.0,
                total_bids=0,
                second_price=None
            )
            
        # Sort desc
        sorted_bids = sorted(valid_bids, key=lambda x: x.amount, reverse=True)
        
        winner = sorted_bids[0]
        second_place = sorted_bids[1] if len(sorted_bids) > 1 else None
        
        # In a Vickrey auction, winner pays the second highest price (or their own if only one bid)
        pay_price = second_place.amount if second_place else winner.amount
        
        return AuctionResult(
            auction_id=auction_id,
            winner_id=winner.bidder_id,
            winning_amount=pay_price,
            total_bids=len(valid_bids),
            second_price=second_place.amount if second_place else None
        )
