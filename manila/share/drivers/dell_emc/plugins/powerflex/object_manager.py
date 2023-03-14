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
from oslo_log import log

LOG = log.getLogger(__name__)

class StorageObjectManager(object):

    def __init__(self, api_url, username, password, verify_ssl_cert=False):
        self.base_url = api_url
        self.rest_username = None
        self.rest_password = None
        self.rest_token = None
        
        self.verify_certificate = verify_ssl_cert

    @staticmethod
    def _get_headers():
        return {"content-type": "application/json"}

    def execute_powerflex_get_request(self, url, **url_params):
        request = self.base_url + url % url_params
        res = requests.get(request,
                           auth=(self.rest_username, self.rest_token),
                           verify=self._get_verify_cert())
        res = self._check_response(res, request)
        response = res.json()
        return res, response

    def execute_powerflex_post_request(self, url, params=None, **url_params):
        if not params:
            params = {}
        request = self.base_url + url % url_params
        res = requests.post(request,
                             data=json.dumps(params),
                             headers=self._get_headers(),
                             auth=(self.rest_username, self.rest_token),
                             verify=self._get_verify_cert())
        res = self._check_response(res, request, False, params)
        response = None
        try:
            response = res.json()
        except ValueError:
            response = None
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
            login.request = self.base_url + login_url
            verify_cert = self._get_verify_cert()
            res = requests.post(login_request,
                                auth=(self.rest_username, self.rest_password),
                                verify=verify_cert)
            token = res.json()
            self.rest_token = token
            LOG.info("Going to perform request again %s with valid token.",
                     request)
            if is_get_request:
                response = requests.get(request,
                                        auth=(
                                            self.rest_username,
                                            self.rest_token
                                            ),
                                        verify=verify_cert)
            else:
                response = request.post(request,
                                        data=json.dumps(params),
                                        headers=self._get_headers(),
                                        auth=(
                                            self.rest_username,
                                            self.rest_token
                                            ),
                                        verify=verify_cert)
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
        :return: "True" if created successfully; "False" otherwise
        """
        params = {
                  "file_system_id": "64089d68-b418-bd46-5342-5eebf5c89622",
                  "path": "/testFS",
                  "name": "testExportManila",
                  "description": "test Export Manila",
                  "default_access": "NO_ACCESS",
                  "min_security": "SYS",
                  "read_write_root_hosts": [
                      "10.225.109.43"
                  ]}
        url = self.base_url + '/v1/nfs-exports'
        LOG.info(f"DATA IS: {params}, URL IS: {url}")
        response = self.execute_powerflex_post_request(url, params)
        LOG.info(response)
        return response.status_code == 201 
