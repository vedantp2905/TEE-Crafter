from pydantic import BaseModel, Field, field_validator

class EmployeeRecord(BaseModel):
    emp_id: str
    salary: float
    department: str
    gender: str # "M", "F", "NB", etc.
    role_level: int # 1-10

    @field_validator('salary')
    def salary_must_be_positive(cls, v):
        if v < 0:
            raise ValueError('must be positive')
        return v
