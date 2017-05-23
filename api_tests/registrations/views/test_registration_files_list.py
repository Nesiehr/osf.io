import pytest

from tests.json_api_test_app import JSONAPITestApp
from api.base.settings.defaults import API_BASE
from api_tests import utils as api_utils
from tests.base import ApiTestCase
from osf_tests.factories import (
    AuthUserFactory,
    ProjectFactory,
    RegistrationFactory
)

@pytest.mark.django_db
class TestRegistrationFilesList(object):

    @pytest.fixture(autouse=True)
    def setUp(self):
        self.app = JSONAPITestApp()
        self.user = AuthUserFactory()
        self.node = ProjectFactory(creator=self.user)
        self.file = api_utils.create_test_file(self.node, self.user, create_guid=False)
        self.file.save()
        self.registration = RegistrationFactory(project=self.node, creator=self.user)

    def test_registration_relationships_contains_guid_not_id(self):
        url = '/{}nodes/{}/files/{}/'.format(API_BASE, self.registration._id, self.file.provider)
        # url = '/{}registrations/{}/files/'.format(API_BASE, self.registration._id)
        res = self.app.get(url, auth=self.user.auth)
        # print res.json
        # print url
        # url = res.json['data'][0]['relationships']['files']['links']['related']['href']
        # res = self.app.get(url, auth=self.user.auth)
        print res.json
        print url
        split_href = res.json['data'][0]['relationships']['files']['links']['related']['href'].split('/')
        assert self.registration._id in split_href
        assert self.registration.id not in split_href
