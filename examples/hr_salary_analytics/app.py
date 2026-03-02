import sys
import json
from models.employee import EmployeeRecord
from analytics.statistics import calculate_equity_stats

def run_app():
    input_str = sys.stdin.read()
    try:
        data = json.loads(input_str)
        records = []
        
        # This app expects a list of employees to perform aggregation on
        if isinstance(data, list):
            for item in data:
                records.append(EmployeeRecord(**item))
        else:
            # If single item, aggregate on one (trivial)
            records.append(EmployeeRecord(**data))
            
        results = calculate_equity_stats(records)
        print(json.dumps(results, indent=2))
        
    except Exception as e:
        print(json.dumps({"error": str(e)}))

if __name__ == "__main__":
    run_app()
