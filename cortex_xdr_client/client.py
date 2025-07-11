from cortex_xdr_client.api.actions_api import ActionsAPI
from cortex_xdr_client.api.alerts_api import AlertsAPI
from cortex_xdr_client.api.authentication import Authentication
from cortex_xdr_client.api.download_api import DownloadAPI
from cortex_xdr_client.api.endpoints_api import EndpointsAPI
from cortex_xdr_client.api.incidents_api import IncidentsAPI
from cortex_xdr_client.api.ioc_api import IocAPI
from cortex_xdr_client.api.scripts_api import ScriptsAPI
from cortex_xdr_client.api.system_api import SystemAPI
from cortex_xdr_client.api.xql_api import XQLAPI


class CortexXDRClient(object):
    incidents_api: IncidentsAPI
    alerts_api: AlertsAPI
    endpoints_api: EndpointsAPI
    scripts_api: ScriptsAPI
    xql_api: XQLAPI
    actions_api: ActionsAPI
    download_api: DownloadAPI
    ioc_api: IocAPI
    system_api: SystemAPI

    def __init__(
        self,
        auth: Authentication,
        fqdn: str,
        default_timeout: tuple[int, int] = (10, 60),
    ) -> None:
        """
        Constructor of the CortexXDRClient class. This class is used to interact with the Cortex XDR API.
        :param auth: The Authentication object containing type
        :param fqdn: The fully qualified domain name of the Cortex XDR server.
        :param default_timeout: The default timeout for API calls.
        """
        self.incidents_api = IncidentsAPI(auth=auth, fqdn=fqdn, timeout=default_timeout)
        self.alerts_api = AlertsAPI(auth=auth, fqdn=fqdn, timeout=default_timeout)
        self.endpoints_api = EndpointsAPI(auth=auth, fqdn=fqdn, timeout=default_timeout)
        self.scripts_api = ScriptsAPI(auth=auth, fqdn=fqdn, timeout=default_timeout)
        self.xql_api = XQLAPI(auth=auth, fqdn=fqdn, timeout=default_timeout)
        self.actions_api = ActionsAPI(auth=auth, fqdn=fqdn, timeout=default_timeout)
        self.download_api = DownloadAPI(auth=auth, fqdn=fqdn, timeout=default_timeout)
        self.ioc_api = IocAPI(auth=auth, fqdn=fqdn, timeout=default_timeout)
        self.system_api = SystemAPI(auth=auth, fqdn=fqdn, timeout=default_timeout)
