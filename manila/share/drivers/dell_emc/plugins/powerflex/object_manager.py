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

import json
import requests
import six
from six.moves import http_client
from six.moves import urllib


from oslo_log import log as logging

LOG = logging.getLogger(__name__)

class StorageObjectManager(object):

    def __init__(self, api_url, username, password, export_path, verify_ssl_cert=False):
        self.base_url = api_url
        self.rest_username = username
        self.rest_password = password
        self.rest_token = None
        self.got_token = False
        self.export_path = export_path
        
        self.verify_certificate = verify_ssl_cert

    def _get_headers(self):
        if self.got_token:
            return {"Content-type": "application/json",
                    "Accept": "application/json",
                    "Authorization": "Bearer " + self.rest_token}
        else:
            return {"Content-type": "application/json",
                    "Accept": "application/json"}

    def execute_powerflex_get_request(self, url, **url_params):
        request = url % url_params
        res = requests.get(request,
                           headers=self._get_headers(),
                           verify=self._get_verify_cert())
        LOG.info(f"REQUEST IN GET IS: {request}")
        LOG.info(f"HEADERS IN GET iARE: {self._get_headers()}")
        LOG.info(f"RES IN GET IS: {res.__dict__}")
        res = self._check_response(res, request)
        response = res.json()
        return res, response

    def execute_powerflex_post_request(self, url, params=None, **url_params):
        if not params:
            params = {}
        request = url % url_params
        LOG.info(f"HEADERS ARE: {self._get_headers()}")
        LOG.info(f"DATA IS: {json.dumps(params)}")
        res = requests.post(request,
                             data=json.dumps(params),
                             headers=self._get_headers(),
                             verify=self._get_verify_cert())
        res = self._check_response(res, request, False, params)
        LOG.info(f"RES IN POST IS: {res.__dict__}")
        response = None
        try:
            response = res.json()
        except ValueError:
            response = None
        LOG.info(f"RESPONSE IN POST IS: {response}")
        return res, response

    def _check_response(self,
                        response,
                        request,
                        is_get_request=True,
                        params=None):
        login_url = "/auth/login"

        if (response.status_code == http_client.UNAUTHORIZED or
                response.status_code == http_client.FORBIDDEN):
            LOG.info("Dell PowerFlex token is invalid, going to re-login "
                     "and get a new one.")
            login_request = self.base_url + login_url
            verify_cert = self._get_verify_cert()
            self.got_token=False
            payload = json.dumps({"username": self.rest_username,
                                   "password": self.rest_password
                      })
            LOG.info(f"PAYLOAD IN CHECK IS: {self._get_headers()}")
            res = requests.post(login_request,
                                headers=self._get_headers(),
                                data=payload,
                                verify=verify_cert)
            token = res.json()["access_token"]
            self.rest_token = token
            self.got_token = True
            LOG.info(f"TOKEN IS: {self.rest_token} AND GOT_TOKEN IS: {self.got_token}")
            LOG.info("Going to perform request again %s with valid token.",
                     request)
            if is_get_request:
                response = requests.get(request,
                                        headers=self._get_headers(),
                                        verify=verify_cert)
            else:
                response = requests.post(request,
                                        headers=self._get_headers(),
                                        data=json.dumps(params),
                                        verify=verify_cert)
                LOG.info(f"HEADERS IN CHECK ARE: {self._get_headers()}")
            level = logging.DEBUG
            if response.status_code != http_client.OK:
                level = logging.ERROR
            LOG.log(level,
                    "REST REQUEST: %s with params %s",
                    request,
                    json.dumps(params))
            LOG.log(level,
                    "REST RESPONSE: %s with params %s",
                    response.status_code,
                    response.text)
            LOG.info(f"RESPONSE IN CHECK IS: {response.__dict__}")
        return response

    def _get_verify_cert(self):
        verify_cert = False
        if self.verify_certificate:
            verify_cert = self.certificate_path
        return verify_cert
   
    def create_nfs_export(self, export_path):
        """Creates an NFS export.
        .
        :param export_path: a string specifying the desired export path
        :return: ID of the export if created successfully
        """
        fs_id = self.get_filesystem_id(export_path)
        LOG.info(f"FS ID IS: {fs_id}")
        params = {
                  "file_system_id": fs_id,
                  "path": "/" + str(export_path),
                  "name": "testExportManila",
                  "description": "test Export Manila",
                  "default_access": "NO_ACCESS",
                  "min_security": "SYS",
                  "read_write_root_hosts": [
                      "10.225.109.43"
                  ]}
        url = self.base_url + '/v1/nfs-exports'
        res, response = self.execute_powerflex_post_request(url, params)
        if res.status_code == 201:
            return response["id"] 

    def get_nfs_export(self, export_id):
        """Retrieves NFS Export properties.

        :id: id of the share
        :return: path of the export
        """
        url = self.base_url + '/v1/nfs-exports/' + export_id + '?select=*'
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return response["name"] 

    def get_filesystem_id(self, export_path):
        """Retrieves an ID for a filesystem.

        :export_path: pathname of the filesystem
        :return: ID of the filesystem
        """
        url = self.base_url + \
              '/v1/file-systems?select=id&name=eq.' + \
              export_path
        res, response = self.execute_powerflex_get_request(url)
        if res.status_code == 200:
            return response[0]['id']
