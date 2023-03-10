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
from manila.share.drivers.dell_emc.plugins import base
from manila.share.drivers.dell_emc.plugins.powerflex import powerflex_api

CONF = cfg.CONF
VERSION = "1.0"

LOG = log.getLogger(__name__)


class PowerFlexStorageConnection(base.StorageConnection):
     """Implements PowerFlex specific functionality for Dell Manila driver."""

     def __init__(self, *args, **kwargs):
         super(PowerFlexStorageConnection, self).__init__(*args, **kwargs)
         LOG.info("Passing through PowerFlex __init__")
         self.server = None
         self._username = None
         self._password = None
         self._server_url = None
         self._root_dir = None
         self._verify_ssl_cert = None
         self._shares = {}

         self._powerflex_api = None
         self._powerflex_api_class = powerflex_api.PowerFlexApi
         self.driver_handles_share_servers = False

    def create_share(self, context, share, share_server):
        """Is called to create share."""
        if share['share_proto'] == 'NFS':
            location = self._create_nfs_share(share)
        else:
            message = (_('Unsupported share protocol: %(proto)s.') %
                       {'proto': share['share_proto']})
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

        return location

    def __get_container_path(self, share):
        """Return path to a container."""
        return os.path.join(self._root_dir, share['name']}

    def _create_nfs_share(self, share):
        """Is called to create nfs share."""
        container_path = self._get_container_path(share)

        share_created = self._powerflex_api.create_nfs_export(container_path)
        if not share_created:
            message = (
                     _('The requested NFS share "%(share)s" was not created.') %
                      {'share': share['name']})
            LOG.error(message)
            raise exception.ShareBackendException(message)
        location = '{0}:{1}'.format(self._server, container_path)
        return location

    def connect(self, dell_share_driver, context):
        """Connect to a PowerFlex system."""
        config = dell_share_driver.configuration
        self._server = config.safe_get( "dell_nas_derver")
        self._server_url = ('https://' + self._server)
        self._username = config.safe_get("dell_nas_login")
        self._password = config.safe_get("dell_nas_password")
        self._root_dir = config.safe_get("dell_nas_root_dir")
        self._verify_ssl_cert = False
        self._powerflex_api = self._powerflex_api_class(self._server_url, auth=(
            self._username, self._password),
            verify_ssl_cert=self._verify_ssl_cert)
