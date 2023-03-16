# Copyright (c) 2023 Dell Inc. or its subsidiaries.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
PowerFlex specific NAS backend plugin.
"""
import os
from oslo_config import cfg
from oslo_log import log
from oslo_utils import units
from requests.exceptions import HTTPError

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.plugins import base as driver
from manila.share.drivers.dell_emc.plugins.powerflex import (
    object_manager as manager )

"""Version history:
    1.0 - Initial version
"""

VERSION = "1.0"

CONF = cfg.CONF

LOG = log.getLogger(__name__)

POWERFLEX_OPTS = [
    cfg.StrOpt('powerflex_storage_pool',
               help='Storage pool used to provision NAS.'),
    cfg.StrOpt('powerflex_protection_domain',
               help='Protection domaian to use.')
]


class PowerFlexStorageConnection(driver.StorageConnection):
    """Implements PowerFlex specific functionality for Dell Manila driver."""

    def __init__(self, *args, **kwargs):
        super(PowerFlexStorageConnection, self).__init__(*args, **kwargs)
        if 'configuration' in kwargs:
            kwargs['configuration'].append_config_values(POWERFLEX_OPTS)

        self.manager = None
        self.server = None
        self._username = None
        self._password = None
        self._server_url = None
        self._root_dir = None
        self._verify_ssl_cert = None
        self._shares = {}
        self.verify_certificate = None
        self.export_path = None

        self.driver_handles_share_servers = False

    def connect(self, dell_share_driver, context):
        """Connect to PowerFlex SDNAS server."""
        config = dell_share_driver.configuration
        get_config_value = config.safe_get
        self.verify_certificates = get_config_value("dell_ssl_cert_verify")
        self.rest_ip = get_config_value("emc_nas_server")
        self.rest_port = (int(get_config_value("emc_nas_server_port")) or
                         443)
        self.nas_server = get_config_value("emc_nas_root_dir")
        self.storage_pool = get_config_value("powerflex_storage_pool")
        self.protection_domain = get_config_value("powerflex_protection_domain")
        self.rest_username = get_config_value("emc_nas_login")
        self.rest_password = get_config_value("emc_nas_password")
        if self.verify_certificate:
            self.certificate_path = get_config_value("dell_ssl_cert_pathicate_path")
        if not all([self.rest_ip, self.rest_username, self.rest_password]):
            message = _("REST server IP, username and password must be specified.")
            raise exception.InvalidInput(reason=message)
        # validate certificate settings
        if self.verify_certificate and not self.certificate_path:
            message = _("Path to REST server's certificate must be specified.")
            raise exception.InvalidInput(reason=msg)
        self.base_url = ("https://%(server_ip)s:%(server_port)s/rest" %
                         {
                             "server_ip": self.rest_ip,
                             "server_port": self.rest_port
                        })
        LOG.info("REST server IP: %(ip)s, port: %(port)s, "
                 "username: %(user)s. Verify server's certificate: "
                 "%(verify_cert)s.",
                 {
                     "ip": self.rest_ip,
                     "port": self.rest_port,
                     "user": self.rest_username,
                     "verify_cert": self.verify_certificate,
                 })

        self.manager = manager.StorageObjectManager(self.base_url,
                                                    self.rest_username,
                                                    self.rest_password,
                                                    self.export_path,
                                                    self.verify_certificate)


    def create_share(self, context, share, share_server):
        """Is called to create a share."""
        LOG.info(f"SHARE SERVER IS: {share_server}")
        if share['share_proto'].upper() == 'NFS':
            location = self._create_nfs_share(share)
        else:
            message = (_('Unsupported share protocol: %(proto)s.') %
                       {'proto': share['share_proto']})
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

        return location

    def allow_access(self, context, share, access, share_server):
        pass

    def create_snapshot(self, context, snapshot, share_server):
        pass

    def delete_snapshot(self, context, snapshot, share_server):
        pass

    def delete_share(self, context, share, share_server):
        pass
        """Is called to delete a share.
        if share['share_proto'].upper() == 'NFS':
            self._delete_nfs_share(share)
        else:
            message = (_('Unsupported share type: %(type)s.') %
                        {'type': share['share_proto']})
            LOG.error(message)
            raise exception.InvalidShare(reason=message)"""

    def deny_access(self, context, share, access, share_server):
        pass

    def ensure_share(self, context, share, share_server):
        pass

    def extend_share(self, share, new_size, share_server=None):
        pass

    def setup_server(self, network_info, metadata=None):
        pass

    def teardown_server(self, server_details, security_services=None):
        pass

    def check_for_setup_error(self):
        pass

    def _create_nfs_share(self, share):
        """Create an NFS share. 
           In PowerFlex, an exporti(share) belongs to a filesystem. """
        size_in_bytes = share['size'] * 1024 * 1024 * 1024
        # Minimum size is 3GiB, that is 3221225472 bytes
        if size_in_bytes >= 3221225472:
            filesystem_id = self.manager.create_filesystem(self.nas_server,
                                                           share['name'],
                                                           size_in_bytes)
            if not filesystem_id:
                message = {
                    _('The requested NFS export "%(share)s" was not created.') %
                     {'share': share['name']}}
                LOG.error(message)
                raise exception.ShareBackendException(message)
            else:
                share_id = self.manager.create_nfs_export(filesystem_id, share['name'])
                if not share_id:
                    message = (
                        _('The requested NFS export "%(share)s" was not created.') %
                         {'share': share['name']})
                    LOG.error(message)
                    raise exception.ShareBackendException(msg=message)
                share_path = self.manager.get_nfs_export_name(share_id)
                location = '{0}:/{1}'.format(self.rest_ip, share_path)
            return location
        else:
            message = (
                _('The requested size for "%(share)s must be bigger than 3GiB.') %
                 {'share': share['name']})
            LOG.error(message)
            raise exception.ShareBackendException(message)

    def _delete_nfs_share(self, share):
        """Delete an NFS share."""
        share_id = self.manager.get_nfs_export_id(share['name'])
        if share_id is None:
            message = ('Attempted to delete NFS Share "%s", but the share does '
                       'not appear to exist.')
            LOG.warning(message, share['name'])
        else:
            export_deleted = self.manager.delete_nfs_export(share_id)
            if not export_deleted:
                message = _('Error deleting NFS exoport: %s') % share['name']
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)
