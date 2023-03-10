# Copyright 2011 OpenStack Foundation
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

import ddt
from oslo_config import cfg
from oslo_serialization import jsonutils
import webob

from manila.api.v1 import share_metadata
from manila.api.v1 import shares
from manila.common import constants
from manila import context
from manila import db
from manila.share import api
from manila import test
from manila.tests.api import fakes

CONF = cfg.CONF
AFFINITY_KEY = constants.AdminOnlyMetadata.AFFINITY_KEY
ANTI_AFFINITY_KEY = constants.AdminOnlyMetadata.ANTI_AFFINITY_KEY


@ddt.ddt
class ShareMetaDataTest(test.TestCase):

    def setUp(self):
        super(ShareMetaDataTest, self).setUp()
        self.share_api = api.API()
        self.share_controller = shares.ShareController()
        self.controller = share_metadata.ShareMetadataController()
        self.ctxt = context.RequestContext('admin', 'fake', True)
        self.origin_metadata = {
            "key1": "value1",
            "key2": "value2",
            "key3": "value3",
        }
        self.share = db.share_create(self.ctxt, {})
        self.share_id = self.share['id']
        self.url = '/shares/%s/metadata' % self.share_id
        db.share_metadata_update(
            self.ctxt, self.share_id, self.origin_metadata, delete=False)

    def test_index(self):
        req = fakes.HTTPRequest.blank(self.url)
        res_dict = self.controller.index(req, self.share_id)

        expected = {
            'metadata': {
                'key1': 'value1',
                'key2': 'value2',
                'key3': 'value3',
            },
        }

        self.assertEqual(expected, res_dict)

    def test_index_nonexistent_share(self):
        req = fakes.HTTPRequest.blank(self.url)
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.index, req, self.url)

    def test_index_no_data(self):
        db.share_metadata_update(
            self.ctxt, self.share_id, {}, delete=True)
        req = fakes.HTTPRequest.blank(self.url)
        res_dict = self.controller.index(req, self.share_id)
        expected = {'metadata': {}}
        self.assertEqual(expected, res_dict)

    def test_show(self):
        req = fakes.HTTPRequest.blank(self.url + '/key2')

        res_dict = self.controller.show(req, self.share_id, 'key2')

        expected = {'meta': {'key2': 'value2'}}
        self.assertEqual(expected, res_dict)

    def test_show_nonexistent_share(self):
        req = fakes.HTTPRequest.blank(self.url + '/key2')
        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.show,
            req, "nonexistent_share", 'key2')

    def test_show_meta_not_found(self):
        req = fakes.HTTPRequest.blank(self.url + '/key6')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show, req, self.share_id, 'key6')

    def test_delete(self):
        req = fakes.HTTPRequest.blank(self.url + '/key2')
        req.method = 'DELETE'
        res = self.controller.delete(req, self.share_id, 'key2')

        self.assertEqual(200, res.status_int)

    def test_delete_nonexistent_share(self):
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'DELETE'
        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.delete,
            req, "nonexistent_share", 'key1')

    def test_delete_meta_not_found(self):
        req = fakes.HTTPRequest.blank(self.url + '/key6')
        req.method = 'DELETE'
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.delete, req, self.share_id, 'key6')

    @ddt.data((AFFINITY_KEY, '/' + AFFINITY_KEY),
              (ANTI_AFFINITY_KEY, '/' + ANTI_AFFINITY_KEY))
    @ddt.unpack
    def test_delete_affinities_user(self, key, path):
        self.userctxt = context.RequestContext('demo', 'fake', False)
        req = fakes.HTTPRequest.blank(self.url + path)
        req.method = 'DELETE'
        req.content_type = "application/json"
        req.environ['manila.context'] = self.userctxt
        establish = {key: 'share1'}
        db.share_metadata_update(
            self.ctxt, self.share_id, establish, delete=False)

        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.delete,
            req, self.share_id, key)

        #  test that nothing was deleted
        data = db.share_metadata_get(self.userctxt, self.share_id)
        if key in data:
            res_dict = {'meta': {key: data[key]}}
        self.assertEqual(res_dict, {'meta': establish})

    @ddt.data((AFFINITY_KEY, '/' + AFFINITY_KEY),
              (ANTI_AFFINITY_KEY, '/' + ANTI_AFFINITY_KEY))
    @ddt.unpack
    def test_delete_affinities_admin(self, key, path):
        req = fakes.HTTPRequest.blank(self.url + path)
        req.method = 'DELETE'
        req.content_type = "application/json"
        admin_context = req.environ['manila.context'].elevated()
        req.environ['manila.context'] = admin_context
        establish = {key: 'share1'}
        db.share_metadata_update(
            self.ctxt, self.share_id, establish, delete=False)

        self.controller.delete(
            req, self.share_id, key)

        #  test that key was deleted
        data = db.share_metadata_get(self.ctxt, self.share_id)
        res_dict = {'meta': data}
        self.assertEqual(res_dict, {'meta': self.origin_metadata})

    def test_create(self):
        req = fakes.HTTPRequest.blank('/v1/share_metadata')
        req.method = 'POST'
        req.content_type = "application/json"
        body = {"metadata": {"key9": "value9"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        res_dict = self.controller.create(req, self.share_id, body)
        expected = self.origin_metadata
        expected.update(body['metadata'])
        self.assertEqual({'metadata': expected}, res_dict)

    def test_create_empty_body(self):
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'POST'
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.share_id, None)

    def test_create_item_empty_key(self):
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"": "value1"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.share_id, body)

    def test_create_item_key_too_long(self):
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {("a" * 260): "value1"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create,
                          req, self.share_id, body)

    def test_create_nonexistent_share(self):
        req = fakes.HTTPRequest.blank('/v1/share_metadata')
        req.method = 'POST'
        req.content_type = "application/json"
        body = {"metadata": {"key9": "value9"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.create,
            req, "nonexistent_share", body)

    def test_update_all(self):
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        expected = {
            'metadata': {
                'key10': 'value10',
                'key99': 'value99',
            },
        }
        req.body = jsonutils.dumps(expected).encode("utf-8")
        res_dict = self.controller.update_all(req, self.share_id, expected)

        self.assertEqual(expected, res_dict)

    def test_update_all_empty_container(self):
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        expected = {'metadata': {}}
        req.body = jsonutils.dumps(expected).encode("utf-8")
        res_dict = self.controller.update_all(req, self.share_id, expected)

        self.assertEqual(expected, res_dict)

    def test_update_all_malformed_container(self):
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        expected = {'meta': {}}
        req.body = jsonutils.dumps(expected).encode("utf-8")

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update_all, req, self.share_id,
                          expected)

    @ddt.data(['asdf'],
              {'key': None},
              {None: 'value'},
              {None: None})
    def test_update_all_malformed_data(self, metadata):
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        expected = {'metadata': metadata}
        req.body = jsonutils.dumps(expected).encode("utf-8")

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update_all, req, self.share_id,
                          expected)

    def test_update_all_nonexistent_share(self):
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        body = {'metadata': {'key10': 'value10'}}
        req.body = jsonutils.dumps(body).encode("utf-8")

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.update_all, req, '100', body)

    @ddt.data({AFFINITY_KEY: 'foo'},
              {ANTI_AFFINITY_KEY: 'foo'},
              {AFFINITY_KEY: 'foo',
               ANTI_AFFINITY_KEY: 'bar'},
              {AFFINITY_KEY: 'foo',
               ANTI_AFFINITY_KEY: 'bar',
               'foo': 'bar'})
    def test_update_all_affinities_user(self, metadata):
        body = {'metadata': metadata}
        self.userctxt = context.RequestContext('demo', 'fake', False)
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        req.environ['manila.context'] = self.userctxt
        establish = {AFFINITY_KEY: 'share1'}
        db.share_metadata_update(
            self.ctxt, self.share_id, establish, delete=False)
        before_update_all = db.share_metadata_get(self.userctxt, self.share_id)

        body = {'metadata': metadata}
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.update_all,
            req, self.share_id, body)

        #  test nothing was deleted or updated
        after_update_all = db.share_metadata_get(self.userctxt, self.share_id)
        self.assertEqual(after_update_all, before_update_all)

    @ddt.data({AFFINITY_KEY: 'foo'},
              {ANTI_AFFINITY_KEY: 'foo'},
              {AFFINITY_KEY: 'foo',
               ANTI_AFFINITY_KEY: 'bar'},
              {AFFINITY_KEY: 'foo',
               ANTI_AFFINITY_KEY: 'bar',
               'foo': 'bar'})
    def test_update_all_affinities_admin(self, metadata):
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'PUT'
        req.content_type = "application/json"
        admin_context = req.environ['manila.context'].elevated()
        req.environ['manila.context'] = admin_context
        establish = {AFFINITY_KEY: 'share1'}
        db.share_metadata_update(
            self.ctxt, self.share_id, establish, delete=False)

        body = {'metadata': metadata}
        req.body = jsonutils.dumps(body).encode("utf-8")
        res_dict = self.controller.update_all(req, self.share_id, body)
        expected = body
        self.assertEqual(res_dict, expected)

    def test_update_item(self):
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"key1": "value1"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.headers["content-type"] = "application/json"
        res_dict = self.controller.update(req, self.share_id, 'key1', body)
        expected = {'meta': {'key1': 'value1'}}
        self.assertEqual(expected, res_dict)

    def test_update_item_nonexistent_share(self):
        req = fakes.HTTPRequest.blank('/v1.1/fake/shares/asdf/metadata/key1')
        req.method = 'PUT'
        body = {"meta": {"key1": "value1"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.headers["content-type"] = "application/json"

        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.update,
            req, "nonexistent_share", 'key1', body)

    def test_update_item_empty_body(self):
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, self.share_id, 'key1',
                          None)

    def test_update_item_empty_key(self):
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"": "value1"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, self.share_id, '', body)

    def test_update_item_key_too_long(self):
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {("a" * 260): "value1"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update,
                          req, self.share_id, ("a" * 260), body)

    def test_update_item_value_too_long(self):
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"key1": ("a" * 1025)}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update,
                          req, self.share_id, "key1", body)

    def test_update_item_too_many_keys(self):
        req = fakes.HTTPRequest.blank(self.url + '/key1')
        req.method = 'PUT'
        body = {"meta": {"key1": "value1", "key2": "value2"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, self.share_id, 'key1',
                          body)

    def test_update_item_body_uri_mismatch(self):
        req = fakes.HTTPRequest.blank(self.url + '/bad')
        req.method = 'PUT'
        body = {"meta": {"key1": "value1"}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        req.headers["content-type"] = "application/json"

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, self.share_id, 'bad',
                          body)

    @ddt.data((AFFINITY_KEY, '/' + AFFINITY_KEY),
              (ANTI_AFFINITY_KEY, '/' + ANTI_AFFINITY_KEY))
    @ddt.unpack
    def test_update_item_affinities_user(self, key, path):
        self.userctxt = context.RequestContext('demo', 'fake', False)
        req = fakes.HTTPRequest.blank(self.url + path)
        req.method = 'PUT'
        req.content_type = "application/json"
        req.environ['manila.context'] = self.userctxt
        establish = {AFFINITY_KEY: 'share1'}
        db.share_metadata_update(
            self.ctxt, self.share_id, establish, delete=False)

        body = {'meta': {key: 'share1,share2'}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.update,
            req, self.share_id, key, body)

        #  test that nothing was updated
        data = db.share_metadata_get(self.ctxt, self.share_id)
        if AFFINITY_KEY in data:
            res_dict = {'meta': {AFFINITY_KEY: data[AFFINITY_KEY]}}
        self.assertEqual(res_dict, {'meta': establish})

    @ddt.data((AFFINITY_KEY, '/' + AFFINITY_KEY),
              (ANTI_AFFINITY_KEY, '/' + ANTI_AFFINITY_KEY))
    @ddt.unpack
    def test_update_item_affinities_admin(self, key, path):
        req = fakes.HTTPRequest.blank(self.url + path)
        req.method = 'PUT'
        req.content_type = "application/json"
        admin_context = req.environ['manila.context'].elevated()
        req.environ['manila.context'] = admin_context
        establish = {AFFINITY_KEY: 'share1'}
        db.share_metadata_update(
            self.ctxt, self.share_id, establish, delete=False)

        body = {'meta': {key: 'share1,share2'}}
        req.body = jsonutils.dumps(body).encode("utf-8")
        res_dict = self.controller.update(
            req, self.share_id, key, body)
        expected = body
        self.assertEqual(res_dict, expected)

    def test_invalid_metadata_items_on_create(self):
        req = fakes.HTTPRequest.blank(self.url)
        req.method = 'POST'
        req.headers["content-type"] = "application/json"

        # test for long key
        data = {"metadata": {"a" * 260: "value1"}}
        req.body = jsonutils.dumps(data).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.share_id, data)

        # test for long value
        data = {"metadata": {"key": "v" * 1025}}
        req.body = jsonutils.dumps(data).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.share_id, data)

        # test for empty key.
        data = {"metadata": {"": "value1"}}
        req.body = jsonutils.dumps(data).encode("utf-8")
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, self.share_id, data)
