import numpy as np
import pandas as pd
from typing import List, Dict
from models.employee import EmployeeRecord

def calculate_equity_stats(records: List[EmployeeRecord]) -> Dict:
    df = pd.DataFrame([r.model_dump() for r in records])
    
    if df.empty:
        return {"status": "no_data"}
        
    stats = {}
    
    # 1. Gender Pay Gap (Unadjusted)
    gender_pay = df.groupby("gender")["salary"].mean().to_dict()
    stats["average_salary_by_gender"] = gender_pay
    
    # 2. Role Level Distribution
    stats["role_distribution"] = df["role_level"].value_counts().to_dict()
    
    # 3. Departmental Stats
    dept_stats = df.groupby("department")["salary"].agg(['mean', 'median', 'std']).fillna(0).to_dict(orient="index")
    stats["department_stats"] = dept_stats
    
    # 4. Outlier Detection (Securely reported count only, no IDs)
    q1 = df["salary"].quantile(0.25)
    q3 = df["salary"].quantile(0.75)
    iqr = q3 - q1
    outliers = df[(df["salary"] < (q1 - 1.5 * iqr)) | (df["salary"] > (q3 + 1.5 * iqr))]
    stats["outlier_count"] = len(outliers)
    
    return stats
