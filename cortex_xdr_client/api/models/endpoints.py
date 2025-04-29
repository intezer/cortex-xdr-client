from enum import Enum
from typing import List
from typing import Optional
from typing import Union

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
    agent_id: Optional[str]
    agent_status: Optional[str]
    host_name: Optional[str]
    agent_type: Optional[str]
    ip: Optional[List[str]]


class GetAllEndpointsResponse(CustomBaseModel):
    reply: List[LightEndpoint]


class Endpoint(CustomBaseModel):
    active_directory: Union[List[str], Optional[str]]
    alias: Optional[str]
    content_version: Optional[str]
    domain: Optional[str]
    endpoint_id: Optional[str]
    endpoint_name: Optional[str]
    endpoint_status: EndpointStatus
    endpoint_type: Optional[str]
    endpoint_version: Optional[str]
    first_seen: Optional[int]
    group_name: Optional[List[str]]
    install_date: Optional[int]
    installation_package: Optional[str]
    ip: Optional[List[str]]
    is_isolated: IsolateStatus
    isolated_date: Optional[str]
    last_seen: Optional[int]
    last_content_update_time: Optional[int]
    operational_status: Optional[str]
    operational_status_description: Optional[str]
    os_type: Optional[EndpointPlatform]
    scan_status: Optional[ScanStatus]
    users: Union[Optional[List[str]], Optional[str]]
    mac_address: Optional[List[str]]
    os_version: Optional[str]
    ipv6: Optional[list[str]]
    public_ip: Optional[str]
    operating_system: Optional[str]
    tags: Optional[dict]


class GetEndpointResponseItem(CustomBaseModel):
    total_count: Optional[int]
    result_count: Optional[int]
    endpoints: List[Endpoint]


class GetEndpointResponse(CustomBaseModel):
    reply: GetEndpointResponseItem


class ResponseActionResponseItem(CustomBaseModel):
    action_id: Optional[str]
    status: Optional[int]
    endpoints_count: Optional[int]


class ResponseActionResponse(CustomBaseModel):
    reply: ResponseActionResponseItem


class ResponseStatusResponse(CustomBaseModel):
    reply: bool
