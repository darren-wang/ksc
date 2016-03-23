# Copyright 2012 Nebula, Inc.
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import datetime

from oslo_utils import timeutils

from keystoneclient.i18n import _
from keystoneclient import service_catalog


# gap, in seconds, to determine whether the given token is about to expire
STALE_TOKEN_DURATION = 30


class AccessInfo(dict):
    """Encapsulates a raw authentication token from keystone.

    Provides helper methods for extracting useful values from that token.

    """

    @classmethod
    def factory(cls, resp=None, body=None, region_name=None, auth_token=None,
                **kwargs):
        """Create AccessInfo object given a successful auth response & body
           or a user-provided dict.
        """
        # FIXME(jamielennox): Passing region_name is deprecated. Provide an
        # appropriate warning.
        auth_ref = None

        if body is not None or len(kwargs):
            if AccessInfoV3.is_valid(body, **kwargs):
                if resp and not auth_token:
                    auth_token = resp.headers['X-Subject-Token']
                # NOTE(jamielennox): these return AccessInfo because they
                # already have auth_token installed on them.
                if body:
                    if region_name:
                        body['token']['region_name'] = region_name
                    return AccessInfoV3(auth_token, **body['token'])
                else:
                    return AccessInfoV3(auth_token, **kwargs)
            else:
                raise NotImplementedError(_('Unrecognized auth response'))

        if auth_token:
            auth_ref.auth_token = auth_token

        return auth_ref

    def __init__(self, *args, **kwargs):
        super(AccessInfo, self).__init__(*args, **kwargs)
        self.service_catalog = service_catalog.ServiceCatalog.factory(
            resource_dict=self, region_name=self._region_name)

    @property
    def _region_name(self):
        return self.get('region_name')

    def will_expire_soon(self, stale_duration=None):
        """Determines if expiration is about to occur.

        :returns: true if expiration is within the given duration
        :rtype: boolean

        """
        stale_duration = (STALE_TOKEN_DURATION if stale_duration is None
                          else stale_duration)
        norm_expires = timeutils.normalize_time(self.expires)
        # (gyee) should we move auth_token.will_expire_soon() to timeutils
        # instead of duplicating code here?
        soon = (timeutils.utcnow() + datetime.timedelta(
                seconds=stale_duration))
        return norm_expires < soon

    @classmethod
    def is_valid(cls, body, **kwargs):
        """Determines if processing v3 token given a successful
        auth body or a user-provided dict.

        :returns: true if auth body matches implementing class
        :rtype: boolean
        """
        raise NotImplementedError()

    def has_service_catalog(self):
        """Returns true if the authorization token has a service catalog.

        :returns: boolean
        """
        raise NotImplementedError()

    @property
    def auth_token(self):
        """Returns the token_id associated with the auth request, to be used
        in headers for authenticating OpenStack API requests.

        :returns: str
        """
        return self['auth_token']

    @auth_token.setter
    def auth_token(self, value):
        self['auth_token'] = value

    @auth_token.deleter
    def auth_token(self):
        try:
            del self['auth_token']
        except KeyError:
            pass

    @property
    def expires(self):
        """Returns the token expiration (as datetime object)

        :returns: datetime
        """
        raise NotImplementedError()

    @property
    def issued(self):
        """Returns the token issue time (as datetime object)

        :returns: datetime
        """
        raise NotImplementedError()

    @property
    def username(self):
        """Returns the username associated with the authentication request.
        First looking for 'name',
        returning that if available, and falling back to 'username' if name
        is unavailable.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def user_id(self):
        """Returns the user id associated with the authentication request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def user_domain_id(self):
        """Returns the domain id of the user associated with the authentication
        request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def user_domain_name(self):
        """Returns the domain name of the user associated with the
        authentication request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def role_ids(self):
        """Returns a list of role ids of the user associated with the
        authentication request.

        :returns: a list of strings of role ids
        """
        raise NotImplementedError()

    @property
    def role_names(self):
        """Returns a list of role names of the user associated with the
        authentication request.

        :returns: a list of strings of role names
        """
        raise NotImplementedError()

    @property
    def domain_name(self):
        """Returns the domain name associated with the authentication token.

        :returns: str or None (if no domain associated with the token)
        """
        raise NotImplementedError()

    @property
    def domain_id(self):
        """Returns the domain id associated with the authentication token.

        :returns: str or None (if no domain associated with the token)
        """
        raise NotImplementedError()

    @property
    def project_name(self):
        """Returns the project name associated with the authentication request.

        :returns: str or None (if no project associated with the token)
        """
        raise NotImplementedError()

    @property
    def scoped(self):
        """Returns true if the authorization token was scoped to a tenant
           (project), and contains a populated service catalog.

           This is deprecated, use project_scoped instead.

        :returns: bool
        """
        raise NotImplementedError()

    @property
    def project_scoped(self):
        """Returns true if the authorization token was scoped to a tenant
           (project).

        :returns: bool
        """
        raise NotImplementedError()

    @property
    def domain_scoped(self):
        """Returns true if the authorization token was scoped to a domain.

        :returns: bool
        """
        raise NotImplementedError()

    @property
    def project_id(self):
        """Returns the project ID associated with the authentication
        request, or None if the authentication request wasn't scoped to a
        project.

        :returns: str or None (if no project associated with the token)
        """
        raise NotImplementedError()

    @property
    def project_domain_id(self):
        """Returns the domain id of the project associated with the
        authentication request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def project_domain_name(self):
        """Returns the domain name of the project associated with the
        authentication request.

        :returns: str
        """
        raise NotImplementedError()

    @property
    def auth_url(self):
        """Returns a tuple of URLs from publicURL and adminURL for the service
        'identity' from the service catalog associated with the authorization
        request. If the authentication request wasn't scoped to a tenant
        (project), this property will return None.

        DEPRECATED: this doesn't correctly handle region name. You should fetch
        it from the service catalog yourself.

        :returns: tuple of urls
        """
        raise NotImplementedError()

    @property
    def management_url(self):
        """Returns the first adminURL for 'identity' from the service catalog
        associated with the authorization request, or None if the
        authentication request wasn't scoped to a tenant (project).

        DEPRECATED: this doesn't correctly handle region name. You should fetch
        it from the service catalog yourself.

        :returns: tuple of urls
        """
        raise NotImplementedError()

    @property
    def version(self):
        """Returns the version of the auth token from identity service.

        :returns: str
        """
        return self.get('version')


class AccessInfoV3(AccessInfo):
    """An object for encapsulating a raw v3 auth token from identity
       service.
    """

    def __init__(self, token, *args, **kwargs):
        super(AccessInfo, self).__init__(*args, **kwargs)
        self.update(version='v3')
        self.service_catalog = service_catalog.ServiceCatalog.factory(
            resource_dict=self,
            token=token,
            region_name=self._region_name)
        if token:
            self.auth_token = token

    @classmethod
    def is_valid(cls, body, **kwargs):
        if body:
            return 'token' in body
        elif kwargs:
            return kwargs.get('version') == 'v3'
        else:
            return False

    def has_service_catalog(self):
        return 'catalog' in self

    @property
    def expires(self):
        return timeutils.parse_isotime(self['expires_at'])

    @property
    def issued(self):
        return timeutils.parse_isotime(self['issued_at'])

    @property
    def user_id(self):
        return self['user']['id']

    @property
    def user_domain_id(self):
        try:
            return self['user']['domain']['id']
        except KeyError:
            raise

    @property
    def user_domain_name(self):
        try:
            return self['user']['domain']['name']
        except KeyError:
            raise

    @property
    def role_ids(self):
        return [r['id'] for r in self.get('roles', [])]

    @property
    def role_names(self):
        return [r['name'] for r in self.get('roles', [])]

    @property
    def username(self):
        return self['user']['name']

    @property
    def domain_name(self):
        domain = self.get('domain')
        if domain:
            return domain['name']

    @property
    def domain_id(self):
        domain = self.get('domain')
        if domain:
            return domain['id']

    @property
    def project_id(self):
        project = self.get('project')
        if project:
            return project['id']

    @property
    def project_domain_id(self):
        project = self.get('project')
        if project:
            return project['domain']['id']

    @property
    def project_domain_name(self):
        project = self.get('project')
        if project:
            return project['domain']['name']

    @property
    def project_name(self):
        project = self.get('project')
        if project:
            return project['name']

    @property
    def scoped(self):
        return ('catalog' in self and self['catalog'] and 'project' in self)

    @property
    def project_scoped(self):
        return 'project' in self

    @property
    def domain_scoped(self):
        return 'domain' in self

    @property
    def auth_url(self):
        # FIXME(jamielennox): this is deprecated in favour of retrieving it
        # from the service catalog. Provide a warning.
        if self.service_catalog:
            return self.service_catalog.get_urls(service_type='identity',
                                                 endpoint_type='public',
                                                 region_name=self._region_name)
        else:
            return None

    @property
    def management_url(self):
        # FIXME(jamielennox): this is deprecated in favour of retrieving it
        # from the service catalog. Provide a warning.
        if self.service_catalog:
            return self.service_catalog.get_urls(service_type='identity',
                                                 endpoint_type='admin',
                                                 region_name=self._region_name)

        else:
            return None
