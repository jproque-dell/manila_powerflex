# Copyright (c) 2014 EMC Corporation.
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
"""EMC Share Driver Plugin Framework."""
from stevedore import extension


class EMCPluginManager(object):
    def __init__(self, namespace):
        self.namespace = namespace
        print(f"NAMESPACE IS: {namespace}")

        self.extension_manager = extension.ExtensionManager(namespace)

    def load_plugin(self, name, *args, **kwargs):
        print(f"ARGS ANE: {args} AND KWARGS ARE: {kwargs}")
        for ext in self.extension_manager.extensions:
            print(f"EXT IS : {ext.__dict__}")
            print(f"NAME IS: {name}")
            if ext.name == name:
                storage_conn = ext.plugin(*args, **kwargs)
                return storage_conn

        return None
