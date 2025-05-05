from datetime import datetime
from pydantic import Field
from pydantic import field_validator

from cortex_xdr_client.api.models.base import CustomBaseModel


class Script(CustomBaseModel):
    script_id: int | None = None
    name: str | None = None
    description: str | None = None
    modification_date: int | None = None
    created_by: str | None = None
    windows_supported: bool | None = None
    linux_supported: bool | None = None
    macos_supported: bool | None = None
    is_high_risk: bool | None = None
    script_uid: str | None = None


class GetScriptsResponse(CustomBaseModel):
    total_count: int | None = None
    result_count: int | None = None
    scripts: list[Script] | None = None


class GetScriptsExecutionStatus(CustomBaseModel):
    general_status: str | None = None
    endpoints_pending: int | None = None
    endpoints_canceled: int | None = None
    endpoints_in_progress: int | None = None
    endpoints_timeout: int | None = None
    endpoints_failed: int | None = None
    endpoints_completed_successfully: int | None = None
    endpoints_pending_abort: int | None = None
    endpoints_aborted: int | None = None
    endpoints_expired: int | None = None


class ScriptIO(CustomBaseModel):
    name: str | None = None
    value: str | None = None
    type: str | None = None


class GetScriptMetadataResponse(CustomBaseModel):
    script_id: int | None = None
    name: str | None = None
    description: str | None = None
    modification_date: int | None = None
    created_by: str | None = None
    is_high_risk: bool | None = None
    windows_supported: bool | None = None
    linux_supported: bool | None = None
    macos_supported: bool | None = None
    script_uid: str | None = None
    entry_point: str | None = None
    script_input: list[ScriptIO] | None = None
    script_output_type: str | None = None
    script_output_dictionary_definitions: list[ScriptIO] | None = None


class ScriptExecutionResult(CustomBaseModel):
    endpoint_name: str | None = None
    endpoint_ip_address: list[str] | None = None
    endpoint_status: str | None = None
    domain: str | None = None
    endpoint_id: str | None = None
    execution_status: str | None = None
    standard_output: str | list[str] | None = None
    retrieved_files: int | None = None
    failed_files: int | None = None
    retention_date: int | None = None


class GetScriptExecutionResults(CustomBaseModel):
    script_name: str | None = None
    script_description: str | None = None
    script_parameters: list[ScriptIO] | None = None
    date_created: datetime | None = None
    scope: str | None = None
    error_message: str | None = None
    results: list[ScriptExecutionResult] | None = None


class GetRunSnippetCodeScriptResults(CustomBaseModel):
    action_id: int | None = None
    endpoints_count: int | None = None
