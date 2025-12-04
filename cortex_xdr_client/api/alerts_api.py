from enum import Enum

from cortex_xdr_client.api.authentication import Authentication
from cortex_xdr_client.api.base_api import BaseAPI
from cortex_xdr_client.api.models.alerts import AlertSeverity
from cortex_xdr_client.api.models.alerts import GetAlertsResponse
from cortex_xdr_client.api.models.alerts import GetAlertsResponseV2
from cortex_xdr_client.api.models.alerts import QuerySortOrder
from cortex_xdr_client.api.models.alerts import QuerySortType
from cortex_xdr_client.api.models.filters import new_request_data
from cortex_xdr_client.api.models.filters import request_filter
from cortex_xdr_client.api.models.filters import request_gte_lte_filter


class AlertsAPI(BaseAPI):
    def __init__(
        self, auth: Authentication, fqdn: str, timeout: tuple[int, int]
    ) -> None:
        super(AlertsAPI, self).__init__(auth, fqdn, "alerts", timeout)

    # https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-apis/incident-management/get-alerts.html
    def get_alerts(
        self,
        alert_id_list: list[int] | None = None,
        alert_source_list: list[str] | None = None,
        severities: list[AlertSeverity] | None = None,
        creation_time: int = None,
        after_creation: bool = False,
        server_creation_time: int = None,
        after_server_creation: bool = False,
        search_from: int = None,
        search_to: int = None,
        sort_type: QuerySortType = None,
        sort_order: QuerySortOrder = QuerySortOrder.ASC,
    ) -> GetAlertsResponse | None:
        """
        Get a list of alerts with multiple events.

        :param alert_id_list: List of integers of the Alert ID
        :param alert_source_list: List of strings of the Alert source
        :param severities: List of strings of the Alert severity
        :param creation_time: Timestamp of the Creation time. Also known as detection_timestamp.
        :param after_creation: If the creation date will be the upper or lower bound limit.
        :param server_creation_time: Timestamp of the Server creation time. Also known as local_insert_ts.
        :param after_server_creation: If the server creation date will be the upper or lower bound limit.
        :param search_to: Integer representing the end offset within the result set after which you do not want incidents returned.
        :param search_from: Integer representing the starting offset within the query result set from which you want incidents returned.
        :param sort_type: The field to sort by the requested alerts.
        :param sort_order: The order of the sorting.
        :return: Returns a GetAlertsResponse object if successful.
        """
        filters = []
        sort = {"field": sort_type, "keyword": sort_order} if sort_type else None

        if alert_id_list is not None:
            filters.append(request_filter("alert_id_list", "in", alert_id_list))

        if alert_source_list is not None:
            filters.append(request_filter("alert_source", "in", alert_source_list))

        if severities is not None and len(severities) > 0:
            filters.append(
                request_filter("severity", "in", get_enum_values(severities))
            )

        if creation_time is not None:
            filters.append(
                request_gte_lte_filter("creation_time", creation_time, after_creation)
            )

        if server_creation_time is not None:
            filters.append(
                request_gte_lte_filter(
                    "server_creation_time", server_creation_time, after_server_creation
                )
            )

        request_data = new_request_data(
            filters=filters, search_from=search_from, search_to=search_to, sort=sort
        )

        response = self._call(
            call_name="get_alerts_multi_events", json_value=request_data
        )
        return GetAlertsResponse.model_validate(response.json())

    def get_alerts_v2(
        self,
        alert_id_list: list[int] | None = None,
        alert_source_list: list[str] | None = None,
        severities: list[AlertSeverity] | None = None,
        creation_time: int = None,
        last_modified_time: int = None,
        after_creation: bool = False,
        server_creation_time: int = None,
        after_server_creation: bool = False,
        exclude_alert_source_list: list[str] | None = None,
        search_from: int = None,
        search_to: int = None,
        sort_type: QuerySortType = None,
        sort_order: QuerySortOrder = QuerySortOrder.ASC,
    ) -> GetAlertsResponseV2 | None:
        """
        Get a list of alerts with multiple events.

        :param alert_id_list: List of integers of the Alert ID
        :param alert_source_list: List of strings of the Alert source
        :param severities: List of strings of the Alert severity
        :param creation_time: Timestamp of the Creation time. Also known as detection_timestamp.
        :param last_modified_time: Timestamp of the Last modified time. Also known as last_modified_ts.
        :param after_creation: If the creation date will be the upper or lower bound limit.
        :param server_creation_time: Timestamp of the Server creation time. Also known as local_insert_ts.
        :param after_server_creation: If the server creation date will be the upper or lower bound limit.
        :param exclude_alert_source_list: List of strings of the Alert source to exclude.
        :param search_to: Integer representing the end offset within the result set after which you do not want incidents returned.
        :param search_from: Integer representing the starting offset within the query result set from which you want incidents returned.
        :param sort_type: The field to sort by the requested alerts.
        :param sort_order: The order of the sorting.
        :return: Returns a GetAlertsResponse object if successful.
        """
        filters = []
        sort = {"field": sort_type, "keyword": sort_order} if sort_type else None

        if alert_id_list is not None:
            filters.append(request_filter("alert_id_list", "in", alert_id_list))

        if alert_source_list is not None:
            filters.append(request_filter("alert_source", "in", alert_source_list))

        if exclude_alert_source_list is not None:
            filters.append(
                request_filter("alert_source", "nin", exclude_alert_source_list)
            )

        if severities is not None and len(severities) > 0:
            filters.append(
                request_filter("severity", "in", get_enum_values(severities))
            )

        if creation_time is not None:
            filters.append(
                request_gte_lte_filter("creation_time", creation_time, after_creation)
            )

        if last_modified_time is not None:
            filters.append(
                request_gte_lte_filter(
                    "last_modified_ts", last_modified_time, after_creation
                )
            )

        if server_creation_time is not None:
            filters.append(
                request_gte_lte_filter(
                    "server_creation_time", server_creation_time, after_server_creation
                )
            )

        request_data = new_request_data(
            filters=filters, search_from=search_from, search_to=search_to, sort=sort
        )

        response = self._call(
            call_name="get_alerts_multi_events",
            json_value=request_data,
            api_version="v2",
        )
        return GetAlertsResponseV2.model_validate(response.json())

    def get_siem_alerts(
        self,
        alert_ids: list[str] | None = None,
        creation_time: int | None = None,
        limit: int = 50,
        page: int = 0,
        sort_type: QuerySortType = QuerySortType.CREATION_TIME,
        sort_order: QuerySortOrder = QuerySortOrder.ASC,
    ) -> GetAlertsResponse | None:
        """
        Get a list of SIEM alerts using page-based pagination.
        This method uses the /alerts/get_alerts endpoint for Cortex XSIAM.

        :param alert_ids: List of alert IDs (as strings)
        :param creation_time: Timestamp of the Creation time in milliseconds
        :param limit: Number of alerts per page (max 100)
        :param page: Page number (0-indexed)
        :param sort_type: The field to sort by the requested alerts (default: CREATION_TIME)
        :param sort_order: The order of the sorting (default: ASC for oldest first)
        :return: Returns a GetAlertsResponse object if successful.
        """
        filters = []

        if alert_ids is not None:
            filters.append(request_filter("alert_id_list", "in", alert_ids))

        if creation_time is not None:
            filters.append(
                request_gte_lte_filter("creation_time", creation_time, True)
            )

        limit = min(limit, 100)
        sort = {"field": sort_type, "keyword": sort_order} if sort_type else None

        request_data = {
            'request_data': {
                'filters': filters,
                'limit': limit,
                'page': page,
            }
        }

        if sort:
            request_data['request_data']['sort'] = sort

        response = self._call(
            call_name="get_alerts",
            json_value=request_data,
        )
        return GetAlertsResponse.model_validate(response.json())

    def get_all_siem_alerts(
        self,
        alert_ids: list[str] | None = None,
        creation_time: int | None = None,
        page_size: int = 50,
        max_alerts: int | None = None,
    ) -> list:
        """
        Get all SIEM alerts across all pages using automatic pagination.
        This method automatically handles pagination and returns all alerts.

        :param alert_ids: List of alert IDs (as strings)
        :param creation_time: Timestamp of the Creation time in milliseconds
        :param page_size: Number of alerts per page (max 100)
        :param max_alerts: Maximum number of alerts to return (None for all)
        :return: Returns a list of Alert objects.
        """
        page_size = min(page_size, 100)
        page = 0
        all_alerts = []
        total_fetched = 0

        while True:
            result = self.get_siem_alerts(
                alert_ids=alert_ids,
                creation_time=creation_time,
                limit=page_size,
                page=page,
                sort_type=QuerySortType.CREATION_TIME,
                sort_order=QuerySortOrder.ASC,
            )

            if not result or not result.reply or not result.reply.alerts:
                break

            alerts = result.reply.alerts
            total_count = result.reply.total_count

            for alert in alerts:
                if max_alerts is not None and total_fetched >= max_alerts:
                    return all_alerts
                all_alerts.append(alert)
                total_fetched += 1

            if len(alerts) < page_size:
                break

            if total_count is not None and total_fetched >= total_count:
                break

            page += 1

        return all_alerts


def get_enum_values(p: list[Enum]) -> list[str]:
    return [e.name for e in p]
