from typing import Dict, Optional, Union

from pydantic import BaseModel

from cortex_xdr_client.api.models.base import CustomBaseModel


class ActionStatuStr(CustomBaseModel):
    # Since we don't know what the returned key of <agent ID>/<endpoint ID> will be.
    __root__: Dict[Union[str, None], Union[str, None]]


class GetActionStatusItem(CustomBaseModel):
    data: Optional[ActionStatuStr]


class GetActionStatus(CustomBaseModel):
    reply: GetActionStatusItem
