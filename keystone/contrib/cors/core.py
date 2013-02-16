# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 eNovance.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import webob

from keystone.common import logging
from keystone.common import wsgi
from keystone import config


CONF = config.CONF
LOG = logging.getLogger(__name__)


class CorsMiddleware(wsgi.Middleware):
    def is_origin_allowed(self, conf, origin):
        return origin in conf or '*' in conf

    def process_request(self, request):
        if request.method != "OPTIONS":
            return
        # TODO(chmou): Figure out why this is not automatically
        allowed_methods = CONF.cors.allowed_methods
        if type(allowed_methods) is not list:
            allowed_methods = allowed_methods.split(',')

        # Prepare the default response
        headers = {'Allow': ', '.join(allowed_methods)}
        resp = webob.Response(status=200, request=request, headers=headers)
        req_origin = request.headers.get('Origin', None)
        if not req_origin:
            msg = "skipping options request without Origin header"
            LOG.warning(msg)
            return

        # If the CORS origin isn't allowed return a 401
        if not self.is_origin_allowed(CONF.cors.allowed_origins,
                                      req_origin):
            # TODO(chmou): figure out how to use exception.Unauthorized
            msg = "Origin not allowed in allowed_origins"
            resp.status = 401
            return resp

        req_ctrlreq = request.headers.get('Access-Control-Request-Method')
        if not req_ctrlreq or (req_ctrlreq not in allowed_methods):
            msg = "Access-Control-Request-Method not in allowed_methods"
            LOG.warning(msg)
            resp.status = 401
            return resp

        # Always allow the x-auth-token header. This ensures
        # clients can always make a request to the resource.
        allow_headers = set()
        allow_headers.update(CONF.cors.allowed_headers)
        allow_headers.add('x-auth-token')
        allow_headers.add('content-type')

        headers['access-control-allow-origin'] = req_origin
        if CONF.cors.max_age is not None:
            headers['access-control-max-age'] = CONF.cors.max_age
        headers['access-control-allow-methods'] = \
            ', '.join(allowed_methods)
        headers['access-control-allow-headers'] = ', '.join(allow_headers)
        resp.headers = headers
        return resp

    # Swift implementation decorate only certain requests,
    # figure out why and if that necessary.
    def process_response(self, request, response):
        # The logic here was interpreted from
        #    http://www.w3.org/TR/cors/#resource-requests

        # Is this a CORS request?
        req_origin = request.headers.get('Origin', None)
        if not req_origin:
            return response

        if not self.is_origin_allowed(CONF.cors.allowed_origins, req_origin):
            response.status = 401
            return response

        expose_headers = ['cache-control', 'content-language',
                          'content-type', 'expires', 'last-modified',
                          'pragma', 'etag', 'x-timestamp', 'x-trans-id',
                          'vary']
        expose_headers.extend(CONF.cors.expose_headers)
        hdr = 'Access-Control-Expose-Headers'
        response.headers[hdr] = ', '.join(expose_headers)
        response.headers['Access-Control-Allow-Origin'] = req_origin
        return response
