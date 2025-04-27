from pydantic import BaseModel


# Define a global base class with custom configuration
class CustomBaseModel(BaseModel):
    class Config:
        extra = 'allow'
        use_enum_values = True
