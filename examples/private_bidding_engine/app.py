import sys
import json
from auction.types import Bid
from auction.engine import VickreyAuctionEngine

def run_app():
    input_str = sys.stdin.read()
    try:
        data = json.loads(input_str)
        bids = []
        
        if isinstance(data, list):
            for item in data:
                bids.append(Bid(**item))
        else:
            # Single bid case (unlikely for an auction engine but supported)
            bids.append(Bid(**data))
            
        # Group by auction ID
        auctions = {}
        for b in bids:
            if b.auction_id not in auctions:
                auctions[b.auction_id] = []
            auctions[b.auction_id].append(b)
            
        engine = VickreyAuctionEngine()
        results = []
        
        for auction_id, auction_bids in auctions.items():
            res = engine.process_auction(auction_id, auction_bids)
            results.append(res.model_dump())
            
        print(json.dumps(results, indent=2))
        
    except Exception as e:
        print(json.dumps({"error": str(e)}))

if __name__ == "__main__":
    run_app()
