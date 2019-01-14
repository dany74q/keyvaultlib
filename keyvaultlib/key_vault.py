import logging
from logging import Logger
# noinspection PyPackageRequirements
from time import sleep
from types import TupleType, DictionaryType
from urlparse import urlsplit, urlunsplit

from azure.keyvault import KeyVaultClient
from azure.keyvault.v7_0.models import KeyVaultErrorException
from msrestazure.azure_active_directory import MSIAuthentication as MSICredentials, ServicePrincipalCredentials


class KeyVaultOAuthClient(KeyVaultClient):
    """
    KeyVaultOAuthClient is a KeyVault client wrapper that supports both MSI and ADAL
    authentication mechanisms.

    It's helpful for scenarios where one is transitioning from ADAL authentication to MSI,
    and exists to save the small code duplication of using either MSIAuthentication or ServicePrincipalCredentials.
    """

    LATEST_SECRET_VERSION = ''
    HTTP_TOO_MANY_REQUESTS = 429
    RETRY_COUNT_EXPONENT_BOUND = 4

    def __init__(self, client_id=None, client_secret=None, tenant_id=None, use_msi=False, logger=None,
                 key_vault_resource_url='https://vault.azure.net', *args, **kwargs):
        # type: (str, str, str, bool, Logger, str, TupleType, DictionaryType) -> None
        """
        Initiates a new key vault client with either MSI or ADAL token providers underneath.

        :param client_id:       An optional (when using System-Assigned MSI only) client ID - Of a user or an-
                                application that is authorized with your KeyVault resources. Required when using User-Assigned MSI and ADAL
        :param client_secret:   An optional (When using MSI) client secret - Of a user or an application that is authorized
                                with your KeyVault resources
        :param tenant_id:       An optional (When using MSI) tenant ID of your KeyVault resources
        :param use_msi:         A flag indicated if the client should use MSI (Managed-Service-Identity) to get an OAuth
                                token for your KeyVault resources
        :param logger:          An optional logger to use in case of initialization errors
        """
        self._logger = logger or logging.getLogger(KeyVaultOAuthClient.__class__.__name__)
        self.resource_url = key_vault_resource_url

        splat_resource_url = list(urlsplit(key_vault_resource_url))
        splat_resource_url[1] = '{key_vault_name}.' + splat_resource_url[1]
        splat_resource_url[2] = '/'
        assert len(splat_resource_url) >= 3, 'Failed to parse key vault resource url={}'.format(key_vault_resource_url)
        self.key_vault_url_template = urlunsplit(splat_resource_url)

        if not use_msi and (not client_id or not client_secret or not tenant_id):
            err = 'You should either use MSI, or pass a valid client ID, secret and tenant ID'
            self._logger.error(err)
            raise ValueError(err)

        self._using_msi = use_msi

        if use_msi:
            msi_creds = MSICredentials(resource=key_vault_resource_url, client_id=client_id)
            super(KeyVaultOAuthClient, self).__init__(msi_creds, *args, **kwargs)
        else:
            adal_creds = ServicePrincipalCredentials(client_id, client_secret, tenant=tenant_id,
                                                     resource=key_vault_resource_url)
            super(KeyVaultOAuthClient, self).__init__(adal_creds, *args, **kwargs)

    def get_secret_with_key_vault_name(self, key_vault_name, secret_name, secret_version=LATEST_SECRET_VERSION,
                                       throttling_retry_attempts=5):
        # type: (str, str, str, int) -> basestring

        """
        Use this wrapper to get a KeyVault secret by KeyVault name (i.e. not by a full URL).
        If successful, the secret's value will be returned, otherwise an error will be logged and an exception thrown.

        :param key_vault_name:  Name of KeyVault resource (e.g. For 'https://mykv.vault.azure.net/' the name is 'mykv')
        :param secret_name:     The secret's name inside the KeyVault resource
        :param secret_version:  An optional version of the secret to fetch (latest being the default)
        :param throttling_retry_attempts:   If > 0, will exponentially retry that many times
        :return:                The secret's value as a string
        """
        key_vault_url = self.key_vault_url_template.format(key_vault_name=key_vault_name)

        for retry_attempt in xrange(throttling_retry_attempts + 1):
            try:
                return self.get_secret(key_vault_url, secret_name, secret_version).value
            except Exception as e:
                if isinstance(e, KeyVaultErrorException) and hasattr(e, 'response') \
                        and hasattr(e.response, 'status_code') \
                        and e.response.status_code == self.HTTP_TOO_MANY_REQUESTS \
                        and retry_attempt < throttling_retry_attempts:

                    retry_time_seconds = 2 ** min(retry_attempt, self.RETRY_COUNT_EXPONENT_BOUND)

                    self._logger.exception('Request was throttled vault={} secret={} version={} using_msi={} '
                                           'retrying_in={} seconds'.format(key_vault_url, secret_name, secret_version,
                                                                           self._using_msi, retry_time_seconds))

                    sleep(retry_time_seconds)
                else:
                    self._logger.exception('Failed retrieving secret vault={} secret={} version={} using_msi={}'.format(
                        key_vault_url, secret_name, secret_version, self._using_msi
                    ))
                    raise e
