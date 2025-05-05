from typing import Any
from typing import get_args

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import field_validator


# Define a global base class with custom configuration
class CustomBaseModel(BaseModel):
    model_config = ConfigDict(
        extra='allow',
        use_enum_values=True,
        populate_by_name=True,
    )

    @field_validator('*', mode='before')
    @classmethod
    def _coerce_str_primitives(cls, v: Any, info):
        field = cls.model_fields[info.field_name]
        annotation = field.annotation

        # get_args() returns a tuple of the union members for both typing.Union[...] and X|Y
        args = get_args(annotation)

        # if it’s exactly str, or an Optional/Union that includes str
        if annotation is str or (args and str in args):
            return None if v is None else str(v)
        return v