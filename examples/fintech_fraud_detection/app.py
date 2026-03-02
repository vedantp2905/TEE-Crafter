import sys
import json
from schemas.transaction import Transaction
from core.scoring import score_transaction

def run_app():
    input_str = sys.stdin.read()
    try:
        data = json.loads(input_str)
        results = []
        
        if isinstance(data, list):
            for item in data:
                txn = Transaction(**item)
                result = score_transaction(txn)
                results.append(result.model_dump())
        else:
            txn = Transaction(**data)
            result = score_transaction(txn)
            results = result.model_dump()
            
        print(json.dumps(results, indent=2, default=str))
        
    except Exception as e:
        # Return generic error structure
        print(json.dumps({"error": str(e)}))

if __name__ == "__main__":
    run_app()
