import sys
import json
from domain.models import InferenceRequest
from domain.inference import BrainHealthModel

def run_app():
    # Initialize model (expensive operation usually done once)
    model = BrainHealthModel()
    
    # Read input from stdin
    input_str = sys.stdin.read()
    
    try:
        data = json.loads(input_str)
        results = []
        
        if isinstance(data, list):
            for item in data:
                # Validate with Pydantic
                req = InferenceRequest(**item)
                # Run Inference
                res = model.predict(req)
                results.append(res.model_dump())
        else:
            req = InferenceRequest(**data)
            res = model.predict(req)
            results = res.model_dump()
            
        print(json.dumps(results, indent=2))
        
    except Exception as e:
        error_res = {"error": str(e), "type": type(e).__name__}
        print(json.dumps(error_res))

if __name__ == "__main__":
    run_app()
