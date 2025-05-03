from pydantic import BaseModel
from pydantic import model_validator


# Define a global base class with custom configuration
class CustomBaseModel(BaseModel):
    class Config:
        extra = 'allow'
        use_enum_values = True
        populate_by_name = True

    @model_validator(mode="before")
    @classmethod
    def handle_optional_fields(cls, v):
        return v if v is not None else None
