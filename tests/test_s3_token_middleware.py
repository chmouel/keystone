import webob


from keystone import test
from keystone.middleware import s3_token
from keystone.openstack.common import jsonutils


class FakeApp(object):
    def __call__(self, env, start_response):
        resp = webob.Response()
        resp.environ = env
        return resp(env, start_response)


class FakeHTTPResponse(object):
    def __init__(self, status, body, reason=None):
        self.status = status
        self.body = body
        self.reason = reason

    def read(self):
        return self.body


class BaseFakeHTTPConnection(object):
    status = 201

    def __init__(self, *args):
        pass

    def request(self, method, path, **kwargs):
        pass

    def close(self):
        pass

    def getresponse(self):
        return self.resp


class GoodFakeHTTPConnection(BaseFakeHTTPConnection):
    def request(self, method, path, **kwargs):
        ret = {'access':
               {'token': {'id': 'TOKEN_ID',
                          'tenant': {'id': 'TENANT_ID'}}}}
        body = jsonutils.dumps(ret)
        status = self.status
        self.resp = FakeHTTPResponse(status, body)


class BaseS3TokenMiddlewareTest(test.TestCase):
    def setUp(self, expected_env=None):
        expected_env = expected_env or {}
        conf = {}
        self.middleware = s3_token.S3Token(FakeApp(), conf)
        super(BaseS3TokenMiddlewareTest, self).setUp()

    def start_fake_response(self, status, headers):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)


class BadS3TokenMiddlewareTest(BaseS3TokenMiddlewareTest):
    def setUp(self):
        super(BadS3TokenMiddlewareTest, self).setUp()
        self.middleware.http_client_class = BaseFakeHTTPConnection

    def test_bogus_authorization(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'badboy'
        req.headers['X-Storage-Token'] = 'token'
        resp = req.get_response(self.middleware)
        invalid_uri = s3_token.deny_request('InvalidURI')
        self.assertEqual(resp.body, invalid_uri.body)
        self.assertEqual(resp.status_int, invalid_uri.status_int)

    def test_not_authorized(self):
        def not_authorized(self, *args, **kwargs):
            self.status = 401,
            self.reason = "Credential signature mismatch"
            body = jsonutils.dumps({"error":
                                    {"message":
                                     self.reason,
                                     "code": self.status, "title":
                                     "Not Authorized"}})
            self.resp = FakeHTTPResponse(self.status,
                                         body,
                                         reason=self.reason)

        self.middleware.http_client_class.request = not_authorized

        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        resp = req.get_response(self.middleware)
        access_denied = s3_token.deny_request('AccessDenied')
        self.assertEqual(resp.status_int, access_denied.status_int)
        self.assertEqual(resp.body, access_denied.body)


class S3TokenMiddlewareTest(BaseS3TokenMiddlewareTest):
    def setUp(self):
        super(S3TokenMiddlewareTest, self).setUp()
        self.middleware.http_client_class = GoodFakeHTTPConnection

    # Ignore the request and pass to the next middleware in the
    # pipeline if no path has been specified.
    def test_no_path_request(self):
        req = webob.Request.blank('/')
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)

    # Ignore the request and pass to the next middleware in the
    # pipeline if no Authorization header has been specified
    def test_without_authorization(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)

    def test_without_auth_storage_token(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'badboy'
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)

    def test_authorized(self):
        req = webob.Request.blank('/v1/AUTH_cfa/c/o')
        req.headers['Authorization'] = 'access:signature'
        req.headers['X-Storage-Token'] = 'token'
        req.get_response(self.middleware)
        self.assertTrue(req.path.startswith('/v1/AUTH_TENANT_ID'))
        self.assertEqual(req.headers['X-Auth-Token'], 'TOKEN_ID')

    def test_authorization_nova_toconnect(self):
        req = webob.Request.blank('/v1/AUTH_swiftint/c/o')
        req.headers['Authorization'] = 'access:FORCED_TENANT_ID:signature'
        req.headers['X-Storage-Token'] = 'token'
        req.get_response(self.middleware)
        path = req.environ['PATH_INFO']
        self.assertTrue(path.startswith('/v1/AUTH_FORCED_TENANT_ID'))
