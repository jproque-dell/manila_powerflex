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


import requests

class PowerFlexApi(object):

    def __init__(self, configuration, is_primary=True):
        self.configuration = configuration
        self.is_primary = is_primary
        self.rest_ip = None
        self.rest_port = None
        self.rest_username = None
        self.rest_password = None
        self.rest_token = None
        self.verify_certificate = None
        self.certificate_path = None
        self.base_url = None
        self.is_configured = False

        @staticmethod
        def _get_hearders():
            return {"content-type": "application/json"}

        @property
        def connection_properties(self):
            return {
                "hostIP": None
                "serverIP": self.rest_ip,
                "serverPort": self.rest_port,
                "serverUsername": self.rest_username,
                }

    def do_setup(self):
        get_config_value = self.configuration.safe_get
        self.verify_certificate = get_config_value("dell_ssl_cert_verify")
        self.rest_ip = get_config_value("dell_nas_server")
        self.rest_port = int(
                get_config_value("dell_nas_server_port") or
                443
                )
        self.rest_username = get_config_value("dell_nas_login")
        self.rest_password = get_config_value("dell_nas_password")
        if self.verify_certificate:
            self.certificate_path = get_config_value("dell_ssl_cert_pathicate_path")
        if not all([self.rest_ip, self.rest_username, self.rest_password]):
            message = _("REST server IP, username and password must be specified.")
            raise exception.InvalidInput(reason=messag)
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
        self.is_configured = True

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
        res = requests.posts(request,
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
            if resposne.status_code != http_client.OK:
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
        pass
  



