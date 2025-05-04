import enum

from cortex_xdr_client.api.models.base import CustomBaseModel


class ActionStatus(enum.StrEnum):
    """
    Enum for action status
    """

    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    CANCELLED = "CANCELLED"
    PENDING_ABORT = "PENDING_ABORT"
    ABORTED = "ABORTED"
    EXPIRED = "EXPIRED"
    COMPLETED_PARTIAL = "COMPLETED_PARTIAL"
    COMPLETED_SUCCESSFULLY = "COMPLETED_SUCCESSFULLY"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class GetActionStatusItem(CustomBaseModel):
    data: dict[str | None, str | None] | None = dict()


class GetActionStatus(CustomBaseModel):
    reply: GetActionStatusItem
