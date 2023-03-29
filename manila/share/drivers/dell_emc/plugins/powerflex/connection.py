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
from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.plugins import base as driver
from manila.share.drivers.dell_emc.plugins.powerflex import (
    object_manager as manager)

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
               help='Protection domain to use.'),
    cfg.StrOpt('dell_nas_backend_host',
               help='Dell NAS backend hostname or IP address.'),
    cfg.StrOpt('dell_nas_backend_port',
               help='Port number to use with the Dell NAS backend.'),
    cfg.StrOpt('dell_nas_server',
               help='Root directory or NAS server which owns the shares.'),
    cfg.StrOpt('dell_nas_login',
               help='User name for the Dell NAS backend.'),
    cfg.StrOpt('dell_nas_password',
               help='Password for the Dell NAS backend.')

]


class PowerFlexStorageConnection(driver.StorageConnection):
    """Implements PowerFlex specific functionality for Dell Manila driver."""

    def __init__(self, *args, **kwargs):
        """Do initialization"""

        LOG.debug('Invoking base constructor for Manila Dell PowerFlex SDNAS Driver.')
        super(PowerFlexStorageConnection, self).__init__(*args, **kwargs)

        LOG.debug('Setting up attributes for Manila Dell PowerFlex SDNAS Driver.')
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
        """Connects to Dell PowerFlex SDNAS server."""
        LOG.debug('Reading configuration parameters for Manila Dell PowerFlex SDNAS Driver.')
        config = dell_share_driver.configuration
        get_config_value = config.safe_get
        self.verify_certificates = get_config_value("dell_ssl_cert_verify")
        self.rest_ip = get_config_value("dell_nas_backend_host")
        self.rest_port = (int(get_config_value("dell_nas_backend_port")) or
                          443)
        self.nas_server = get_config_value("dell_nas_server")
        self.storage_pool = get_config_value("powerflex_storage_pool")
        self.protection_domain = get_config_value(
            "powerflex_protection_domain")
        self.rest_username = get_config_value("dell_nas_login")
        self.rest_password = get_config_value("dell_nas_password")
        if self.verify_certificate:
            self.certificate_path = get_config_value(
                "dell_ssl_certificate_path")
        if not all([self.rest_ip,
                    self.rest_username,
                    self.rest_password]):
            message = _("REST server IP, username and password"
                        " must be specified.")
            raise exception.InvalidInput(reason=message)
        # validate certificate settings
        if self.verify_certificate and not self.certificate_path:
            message = _("Path to REST server's certificate must be specified.")
            raise exception.InvalidInput(reason=message)

        LOG.debug('Initializing Dell PowerFlex SDNAS Layer.')
        self.host_url = ("https://%(server_ip)s:%(server_port)s" %
                         {
                             "server_ip": self.rest_ip,
                             "server_port": self.rest_port})
        LOG.info("REST server IP: %(ip)s, port: %(port)s, "
                 "username: %(user)s. Verify server's certificate: "
                 "%(verify_cert)s.",
                 {
                     "ip": self.rest_ip,
                     "port": self.rest_port,
                     "user": self.rest_username,
                     "verify_cert": self.verify_certificate,
                 })

        self.manager = manager.StorageObjectManager(self.host_url,
                                                    self.rest_username,
                                                    self.rest_password,
                                                    self.export_path,
                                                    self.verify_certificate)

    def create_share(self, context, share, share_server):
        """Is called to create a share."""
        if share['share_proto'].upper() == 'NFS':
            LOG.debug('Found NFS share protocol, creating NFS share.')
            location = self._create_nfs_share(share)
        else:
            message = (_('Unsupported share protocol: %(proto)s.') %
                       {'proto': share['share_proto']})
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Is called to create a share from an existing snapshot."""
        raise NotImplementedError()

    def allow_access(self, context, share, access, share_server):
        """Is called to allow access to a share."""
        raise NotImplementedError()

    def check_for_setup_error(self):
        """Is called to check for setup error."""

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Is called to update share access."""
        if share['share_proto'].upper() == 'NFS':
            LOG.debug('Found NFS share protocol, updating access to NFS share.')
            self._update_nfs_access(share, access_rules)
        else:
            message = (_('Unsupported share protocol: %(proto)s.') %
                       {'proto': share['share_proto']})
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

    def create_snapshot(self, context, snapshot, share_server):
        """Is called to create snapshot."""
        export_name = snapshot['share_name']
        LOG.debug(f'Retrieving filesystem ID for share {export_name}')
        filesystem_id = self.manager.get_fsid_from_export_name(export_name)
        LOG.debug(f'Retrieving snapshot ID for filesystem {filesystem_id}')
        snapshot_id = self.manager.create_snapshot(snapshot['name'], filesystem_id)
        if snapshot_id:
            LOG.info("Snapshot %(id)s successfully created.",
                     {'id': snapshot['id']})

    def delete_snapshot(self, context, snapshot, share_server):
        """Is called to delete snapshot."""
        snapshot_name = snapshot['name']
        filesystem_id = self.manager.get_fsid_from_snapshot_name(snapshot_name)
        LOG.debug(f'Retrieving filesystem ID for snapshot {snapshot_name}')
        snapshot_deleted = self.manager.delete_filesystem(filesystem_id)
        if not snapshot_deleted:
            message = (
                _('Failed to delete snapshot "%(snapshot)s".') %
                {'snapshot': snapshot['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        else:
            LOG.info("Snapshot %(id)s successfully deleted.",
                     {'id': snapshot['id']})

    def delete_share(self, context, share, share_server):
        """Is called to delete a share."""
        if share['share_proto'].upper() == 'NFS':
            LOG.debug('Found NFS share protocol, deleting NFS share.')
            self._delete_nfs_share(share)
        else:
            message = (_('Unsupported share type: %(type)s.') %
                       {'type': share['share_proto']})
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

    def deny_access(self, context, share, access, share_server):
        """Is called to deny access to a share."""
        raise NotImplementedError()

    def ensure_share(self, context, share, share_server):
        """Is called to ensure a share is exported."""

    def extend_share(self, share, new_size, share_server=None):
        """Is called to extend a share."""
        # Converts the size from GiB to Bytes
        new_size_in_bytes = new_size * units.Gi
        LOG.debug(f"Extending {share['name']} to {new_size_in_bytes}")
        filesystem_id = self.manager.get_filesystem_id(share['name'])
        self.manager.extend_export(filesystem_id,
                                   new_size_in_bytes)

    def setup_server(self, network_info, metadata=None):
        """Is called to set up a share server.
        Requires driver_handles_share_servers to be True."""
        raise NotImplementedError()

    def teardown_server(self, server_details, security_services=None):
        """Is called to teardown a share server.
        Requires driver_handles_share_servers to be True."""
        raise NotImplementedError()

    def _create_nfs_share(self, share):
        """Creates an NFS share.
        In PowerFlex, an export (share) belongs to a filesystem.
        This function creates a filesystem and an export."""
        size_in_bytes = share['size'] * units.Gi
        # Minimum size is 3GiB, that is 3221225472 bytes
        if size_in_bytes >= 3221225472:
            LOG.debug(f'Retrieving Storage Pool ID for {self.storage_pool}')
            storage_pool_id = self.manager.get_storage_pool_id(
                self.protection_domain,
                self.storage_pool)
            LOG.debug(f"Creating filesystem {share['name']}")
            filesystem_id = self.manager.create_filesystem(storage_pool_id,
                                                           self.nas_server,
                                                           share['name'],
                                                           size_in_bytes)
            if not filesystem_id:
                message = {
                    _('The requested NFS export "%(export)s"'
                      ' was not created.') %
                    {'export': share['name']}}
                LOG.error(message)
                raise exception.ShareBackendException(message)
            else:
                LOG.debug(f"Creating export {share['name']}")
                export_id = self.manager.create_nfs_export(filesystem_id,
                                                           share['name'])
                if not export_id:
                    message = (
                        _('The requested NFS export "%(export)s"'
                          ' was not created.') %
                        {'export': share['name']})
                    LOG.error(message)
                    raise exception.ShareBackendException(msg=message)
                export_path = self.manager.get_nfs_export_name(export_id)
                location = '{0}:/{1}'.format(self.rest_ip, export_path)
            return location
        else:
            message = (
                _('The requested size for "%(export)s must be'
                  ' bigger than 3GiB.') %
                {'export': share['name']})
            LOG.error(message)
            raise exception.ShareBackendException(message)

    def _delete_nfs_share(self, share):
        """Deletes a filesystem and its associated export."""
        filesystem_id = self.manager.get_filesystem_id(share['name'])
        LOG.debug(f"Retrieving filesystem ID for filesystem {share['name']}")
        if filesystem_id is None:
            message = ('Attempted to delete NFS export "%s",'
                       ' but the export does not appear to exist.')
            LOG.warning(message, share['name'])
        else:
            LOG.debug(f"Deleting filesystem ID {filesystem_id}")
            share_deleted = self.manager.delete_filesystem(filesystem_id)
            if not share_deleted:
                message = (
                    _('Failed to delete NFS export "%(export)s".') %
                    {'export': share['name']})
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)

    def _update_nfs_access(self, share, access_rules):
        """Updates access rules for NFS share type."""
        nfs_rw_ips = set()
        nfs_ro_ips = set()

        for rule in access_rules:
            if rule['access_type'].lower() != 'ip':
                message = (_("Only IP access type currently supported for "
                             "NFS. Share provided %(share)s with rule type "
                             "%(type)s") % {'share': share['display_name'],
                                            'type': rule['access_type']})
                LOG.error(message)
                raise exception.InvalidShareAccess(reason=message)

            else:
                if rule['access_level'] == const.ACCESS_LEVEL_RW:
                    nfs_rw_ips.add(rule['access_to'])
                elif rule['access_level'] == const.ACCESS_LEVEL_RO:
                    nfs_ro_ips.add(rule['access_to'])

            share_id = self.manager.get_nfs_export_id(share['name'])
            share_updated = self.manager.set_export_access(share_id,
                                                           nfs_rw_ips,
                                                           nfs_ro_ips)
            if not share_updated:
                message = (
                    _('Failed to update NFS access rules for "%(export)s".') %
                    {'export': share['display_name']})
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)
