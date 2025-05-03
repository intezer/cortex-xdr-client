from enum import Enum

from cortex_xdr_client.api.models.base import CustomBaseModel


class EndpointQuerySortType(str, Enum):
    """
    XDR query sort type.
    """

    ENDPOINT_ID = "endpoint_id"
    FIRST_SEEN = "first_seen"
    LAST_SEEN = "last_seen"
    SCAN_STATUS = "scan_status"


class EndpointStatus(Enum):
    """
    Enum for endpoint status
    """

    connected = "CONNECTED"
    disconnected = "DISCONNECTED"
    lost = "LOST"
    uninstalled = "UNINSTALLED"


class EndpointPlatform(Enum):
    """
    Enum for endpoint platform
    """

    android = "AGENT_OS_ANDROID"
    linux = "AGENT_OS_LINUX"
    windows = "AGENT_OS_WINDOWS"
    macos = "AGENT_OS_MACOS"
    ios = "AGENT_OS_IOS"
    mac = "AGENT_OS_MAC"


class IsolateStatus(Enum):
    """
    Enum for isolate status
    """

    isolated = "AGENT_ISOLATED"
    unisolated = "AGENT_UNISOLATED"
    pending_isolation = "AGENT_PENDING_ISOLATION"
    agent_pending_isolation_cancellation = "AGENT_PENDING_ISOLATION_CANCELLATION"


class ScanStatus(Enum):
    """
    Enum for scan status
    """

    none = "SCAN_STATUS_NONE"
    pending = "SCAN_STATUS_PENDING"
    in_progress = "SCAN_STATUS_IN_PROGRESS"
    canceled = "SCAN_STATUS_CANCELED"
    cancel = "SCAN_STATUS_CANCEL"
    aborted = "SCAN_STATUS_ABORTED"
    pending_cancellation = "SCAN_STATUS_PENDING_CANCELLATION"
    success = "SCAN_STATUS_SUCCESS"
    error = "SCAN_STATUS_ERROR"
    timeout = "SCAN_STATUS_TIMEOUT"


class LightEndpoint(CustomBaseModel):
    agent_id: str | None = None
    agent_status: str | None = None
    host_name: str | None = None
    agent_type: str | None = None
    ip: list[str] | None = None


class GetAllEndpointsResponse(CustomBaseModel):
    reply: list[LightEndpoint]


class Endpoint(CustomBaseModel):
    active_directory: list[str] | str | None = None
    alias: str | None = None
    content_version: str | None = None
    domain: str | None = None
    endpoint_id: str | None = None
    endpoint_name: str | None = None
    endpoint_status: EndpointStatus
    endpoint_type: str | None = None
    endpoint_version: str | None = None
    first_seen: int | None = None
    group_name: list[str] | None = None
    install_date: int | None = None
    installation_package: str | None = None
    ip: list[str] | None = None
    is_isolated: IsolateStatus
    isolated_date: str | None = None
    last_seen: int | None = None
    last_content_update_time: int | None = None
    operational_status: str | None = None
    operational_status_description: str | None = None
    os_type: EndpointPlatform | None = None
    scan_status: ScanStatus | None = None
    users: list[str] | str | None = None
    mac_address: list[str] | None = None
    os_version: str | None = None
    ipv6: list[str] | None = None
    public_ip: str | None = None
    operating_system: str | None = None
    tags: dict | None = None


class GetEndpointResponseItem(CustomBaseModel):
    total_count: int | None = None
    result_count: int | None = None
    endpoints: list[Endpoint]


class GetEndpointResponse(CustomBaseModel):
    reply: GetEndpointResponseItem


class ResponseActionResponseItem(CustomBaseModel):
    action_id: str | None = None
    status: int | None = None
    endpoints_count: int | None = None


class ResponseActionResponse(CustomBaseModel):
    reply: ResponseActionResponseItem


class ResponseStatusResponse(CustomBaseModel):
    reply: bool
