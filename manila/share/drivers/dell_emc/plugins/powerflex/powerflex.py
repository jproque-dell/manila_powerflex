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
        """Is called to create a share."""
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

    def delete_share(self, context, share, share_server):
        pass

    def delete_snapshot(self, context, snapshot, share_server):
        pass

    def delete_share(self, context, share, share_server):
        pass

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

    def _create_nfs_share(self, share_name, share_server):
        """ Create an NFS share."""
        LOG.info("Calling PowerFlex API")

