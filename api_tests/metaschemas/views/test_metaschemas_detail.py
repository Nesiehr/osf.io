import pytest

from website.project.metadata.schemas import ACTIVE_META_SCHEMAS, LATEST_SCHEMA_VERSION
from website.project.model import ensure_schemas, MetaSchema, Q
from api.base.settings.defaults import API_BASE
from tests.json_api_test_app import JSONAPITestApp
from tests.base import ApiTestCase
from osf_tests.factories import (
    AuthUserFactory
)

@pytest.mark.django_db
class TestMetaSchemaDetail(object):

    @pytest.fixture(autouse=True)
    def setUp(self):
        self.app = JSONAPITestApp()
        self.user = AuthUserFactory()
        ensure_schemas()
        self.schema = MetaSchema.find_one(Q('name', 'eq', 'Prereg Challenge') & Q('schema_version', 'eq', LATEST_SCHEMA_VERSION))
        self.url = '/{}metaschemas/{}/'.format(API_BASE, self.schema._id)

    def test_pass_authenticated_user_can_retrieve_schema(self):
        res = self.app.get(self.url, auth=self.user.auth)
        assert res.status_code == 200
        data = res.json['data']['attributes']
        assert data['name'] == 'Prereg Challenge'
        assert data['schema_version'] == 2
        assert res.json['data']['id'] == self.schema._id
        assert data['name'] in ACTIVE_META_SCHEMAS

    def test_pass_unauthenticated_user_can_view_schemas(self):
        res = self.app.get(self.url)
        assert res.status_code == 200

    def test_inactive_metaschema_not_returned(self):
        self.schema = MetaSchema.find_one(Q('name', 'eq', 'Open-Ended Registration') & Q('schema_version', 'eq', 1))
        self.url = '/{}metaschemas/{}/'.format(API_BASE, self.schema._id)
        res = self.app.get(self.url, auth=self.user.auth, expect_errors=True)
        assert res.status_code == 404
