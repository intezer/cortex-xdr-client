from enum import Enum
from typing import List
from typing import Optional

from pydantic import BaseModel

from cortex_xdr_client.api.models.base import CustomBaseModel


class IncidentStatus(str, Enum):
    """
    Incident Status Enum
    Represents the status of the incident.
    """

    NEW = "new"
    UNDER_INVESTIGATION = "under_investigation"
    RESOLVED_THREAT_HANDLED = "resolved_threat_handled"
    RESOLVED_KNOWN_ISSUE = "resolved_known_issue"
    RESOLVED_DUPLICATE_INCIDENT = "resolved_duplicate_incident"
    RESOLVED_DUPLICATE = "resolved_duplicate"
    RESOLVED_FALSE_POSITIVE = "resolved_false_positive"
    RESOLVED_TRUE_POSITIVE = "resolved_true_positive"
    RESOLVED_AUTO_RESOLVE = "resolved_auto_resolve"
    RESOLVED_AUTO = "resolved_auto"
    RESOLVED_OTHER = "resolved_other"
    RESOLVED_SECURITY_TESTING = "resolved_security_testing"


class UpdateIncidentResponse(BaseModel):
    reply: bool


class Incident(CustomBaseModel):
    alert_categories: list[str] | None = None
    alert_count: int | None = None
    alerts_grouping_status: str | None = None
    assigned_user_mail: str | None = None
    assigned_user_pretty_name: str | None = None
    creation_time: int | None = None
    description: str | None = None
    detection_time: int | None = None
    high_severity_alert_count: int | None = None
    host_count: int | None = None
    hosts: list[str] | None = None
    incident_id: str | None = None
    incident_name: str | None = None
    incident_sources: list[str] | None = None
    low_severity_alert_count: int | None = None
    manual_description: str | None = None
    manual_score: int | None = None
    manual_severity: str | None = None
    med_severity_alert_count: int | None = None
    mitre_tactics_ids_and_names: list[str] | None = None
    mitre_techniques_ids_and_names: list[str] | None = None
    modification_time: int | None = None
    notes: str | None = None
    resolve_comment: str | None = None
    rule_based_score: int | None = None
    severity: str | None = None
    starred: bool | None = None
    status: IncidentStatus
    user_count: int | None = None
    users: list[str] | None = None
    wildfire_hits: int | None = None
    xdr_url: str | None = None


class GetIncidentsResponseItem(CustomBaseModel):
    total_count: int | None = None
    result_count: int | None = None
    incidents: List[Incident]


class GetIncidentsResponse(CustomBaseModel):
    reply: GetIncidentsResponseItem


class AlertsDatum(CustomBaseModel):
    action: str | None = None
    action_country: str | None = None
    action_external_hostname: str | None = None
    action_file_macro_sha256: str | None = None
    action_file_md5: str | None = None
    action_file_name: str | None = None
    action_file_path: str | None = None
    action_file_sha256: str | None = None
    action_local_ip: str | None = None
    action_local_port: int | None = None
    action_pretty: str | None = None
    action_process_causality_id: str | None = None
    action_process_image_command_line: str | None = None
    action_process_image_name: str | None = None
    action_process_image_sha256: str | None = None
    action_process_instance_id: str | None = None
    action_process_signature_status: str | None = None
    action_process_signature_vendor: str | None = None
    action_registry_data: str | None = None
    action_registry_full_key: str | None = None
    action_registry_key_name: str | None = None
    action_registry_value_name: str | None = None
    action_remote_ip: str | None = None
    action_remote_port: int | None = None
    actor_causality_id: str | None = None
    actor_process_causality_id: str | None = None
    actor_process_command_line: str | None = None
    actor_process_image_md5: str | None = None
    actor_process_image_name: str | None = None
    actor_process_image_path: str | None = None
    actor_process_image_sha256: str | None = None
    actor_process_instance_id: str | None = None
    actor_process_os_pid: str | None = None
    actor_process_signature_status: str | None = None
    actor_process_signature_vendor: str | None = None
    actor_thread_thread_id: str | None = None
    agent_data_collection_status: str | None = None
    agent_device_domain: str | None = None
    agent_fqdn: str | None = None
    agent_host_boot_time: str | None = None
    agent_install_type: str | None = None
    agent_is_vdi: str | None = None
    agent_os_sub_type: str | None = None
    agent_os_type: str | None = None
    agent_version: str | None = None
    alert_id: int | None = None
    association_strength: str | None = None
    attempt_counter: str | None = None
    bioc_category_enum_key: str | None = None
    bioc_indicator: str | None = None
    case_id: int | None = None
    category: str | None = None
    causality_actor_causality_id: str | None = None
    causality_actor_process_command_line: str | None = None
    causality_actor_process_execution_time: str | None = None
    causality_actor_process_image_md5: str | None = None
    causality_actor_process_image_name: str | None = None
    causality_actor_process_image_path: str | None = None
    causality_actor_process_image_sha256: str | None = None
    causality_actor_process_signature_status: str | None = None
    causality_actor_process_signature_vendor: str | None = None
    contains_featured_host: str | None = None
    contains_featured_ip_address: str | None = None
    contains_featured_user: str | None = None
    deduplicate_tokens: str | None = None
    description: str | None = None
    detection_timestamp: int | None = None
    dns_query_name: str | None = None
    dst_action_country: str | None = None
    dst_action_external_hostname: str | None = None
    dst_action_external_port: str | None = None
    dst_agent_id: str | None = None
    dst_association_strength: str | None = None
    dst_causality_actor_process_execution_time: str | None = None
    end_match_attempt_ts: str | None = None
    endpoint_id: str | None = None
    event_id: str | None = None
    event_sub_type: str | None = None
    event_timestamp: str | None = None
    event_type: str | None = None
    external_id: str | None = None
    filter_rule_id: str | None = None
    fw_app_category: str | None = None
    fw_app_id: str | None = None
    fw_app_subcategory: str | None = None
    fw_app_technology: str | None = None
    fw_device_name: str | None = None
    fw_email_recipient: str | None = None
    fw_email_sender: str | None = None
    fw_email_subject: str | None = None
    fw_interface_from: str | None = None
    fw_interface_to: str | None = None
    fw_is_phishing: str | None = None
    fw_misc: str | None = None
    fw_rule: str | None = None
    fw_rule_id: str | None = None
    fw_serial_number: str | None = None
    fw_url_domain: str | None = None
    fw_vsys: str | None = None
    fw_xff: str | None = None
    host_ip: str | None = None
    host_name: str | None = None
    is_whitelisted: bool | None = None
    local_insert_ts: int | None = None
    mac: str | None = None
    matching_service_rule_id: str | None = None
    matching_status: str | None = None
    mitre_tactic_id_and_name: str | None = None
    mitre_technique_id_and_name: str | None = None
    module_id: str | None = None
    name: str | None = None
    os_actor_causality_id: str | None = None
    os_actor_effective_username: str | None = None
    os_actor_process_causality_id: str | None = None
    os_actor_process_command_line: str | None = None
    os_actor_process_image_name: str | None = None
    os_actor_process_image_path: str | None = None
    os_actor_process_image_sha256: str | None = None
    os_actor_process_instance_id: str | None = None
    os_actor_process_os_pid: str | None = None
    os_actor_process_signature_status: str | None = None
    os_actor_process_signature_vendor: str | None = None
    os_actor_thread_thread_id: str | None = None
    severity: str | None = None
    source: str | None = None
    starred: bool | None = None
    story_id: str | None = None
    user_name: str | None = None


class NetworkArtifactsDatum(CustomBaseModel):
    alert_count: int | None = None
    is_manual: bool | None = None
    network_country: str | None = None
    network_domain: str | None = None
    network_remote_ip: str | None = None
    network_remote_port: int | None = None
    type: str | None = None


class AlertDatums(CustomBaseModel):
    total_count: int | None = None
    data: List[AlertsDatum]


class NetworkArtifacts(CustomBaseModel):
    total_count: int | None = None
    data: List[NetworkArtifactsDatum]


class GetExtraIncidentDataResponseItem(CustomBaseModel):
    alerts: AlertDatums
    file_artifacts: AlertDatums
    incident: Incident
    network_artifacts: NetworkArtifacts


class GetExtraIncidentDataResponse(CustomBaseModel):
    reply: GetExtraIncidentDataResponseItem
