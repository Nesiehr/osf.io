import pytest
import mock

from framework.auth.core import Auth
from osf.models import AbstractNode as Node
from website.util import permissions
from api.base.settings.defaults import API_BASE
from rest_framework import exceptions
from osf_tests.factories import (
    NodeFactory,
    ProjectFactory,
    RegistrationFactory,
    AuthUserFactory,
    WithdrawnRegistrationFactory,
    ForkFactory
)

@pytest.fixture()
def user():
    return AuthUserFactory()

@pytest.mark.django_db
class TestRegistrationForksList:

    @pytest.fixture()
    def pointer(self, user):
        return ProjectFactory(creator=user)

    @pytest.fixture()
    def project_private(self, user, pointer):
        project_private = ProjectFactory(creator=user)
        project_private.add_pointer(pointer, auth=Auth(user), save=True)
        return project_private

    @pytest.fixture()
    def project_public(self, user):
        return ProjectFactory(is_public=True, creator=user)

    @pytest.fixture()
    def component_private(self, user, project_private):
        return NodeFactory(parent=project_private, creator=user)

    @pytest.fixture()
    def component_public(self, user, project_public):
        return NodeFactory(parent=project_public, creator=user, is_public=True)

    @pytest.fixture()
    def registration_private(self, user, project_private, component_private):
        return RegistrationFactory(project=project_private, creator=user)

    @pytest.fixture()
    def registration_public(self, user, project_public, component_public):
        return RegistrationFactory(project = project_public, creator=user, is_public=True)

    @pytest.fixture()
    def fork_private(self, user, registration_private):
        return ForkFactory(project=registration_private, user=user)

    @pytest.fixture()
    def fork_public(self, user, registration_public):
        return ForkFactory(project=registration_public, user=user)

    @pytest.fixture()
    def url_registration_private(self, registration_private):
        return '/{}registrations/{}/forks/'.format(API_BASE, registration_private._id)

    @pytest.fixture()
    def url_registration_public(self, registration_public):
        return '/{}registrations/{}/forks/'.format(API_BASE, registration_public._id)

    def test_can_access_registration_public_forks_list_when_unauthenticated(self, app, registration_public, fork_public, url_registration_public):
        res = app.get(url_registration_public)
        assert len(res.json['data']) == 0
        # Fork defaults to private
        assert fork_public.is_public == False

        fork_public.is_public = True
        fork_public.save()

        res = app.get(url_registration_public)
        assert res.status_code == 200
        assert len(res.json['data']) == 1
        assert fork_public.is_public is True
        data = res.json['data'][0]
        assert data['attributes']['title'] == 'Fork of ' + registration_public.title
        assert data['id'] == fork_public._id
        assert data['attributes']['registration'] == False
        assert data['attributes']['fork'] is True

    def test_can_access_registration_public_forks_list_authenticated_contributor(self, app, user, project_public, url_registration_public, fork_public):
        res = app.get(url_registration_public, auth=user.auth)
        assert res.status_code == 200

        assert fork_public.is_public == False
        assert len(res.json['data']) == 1
        data = res.json['data'][0]
        assert data['attributes']['title'] == 'Fork of ' + project_public.title
        assert data['id'] == fork_public._id
        assert data['attributes']['registration'] == False
        assert data['attributes']['fork'] is True

    def test_can_access_registration_public_forks_list_authenticated_non_contributor(self, app, project_public, url_registration_public, fork_public):
        non_contributor = AuthUserFactory()

        res = app.get(url_registration_public, auth=non_contributor.auth)
        assert res.status_code == 200

        assert len(res.json['data']) == 0
        # Fork defaults to private
        assert fork_public.is_public == False

        fork_public.is_public = True
        fork_public.save()

        res = app.get(url_registration_public)
        assert len(res.json['data']) == 1
        assert fork_public.is_public is True
        data = res.json['data'][0]
        assert data['attributes']['title'] == 'Fork of ' + project_public.title
        assert data['id'] == fork_public._id
        assert data['attributes']['registration'] == False
        assert data['attributes']['fork'] is True

    def test_authentication(self, app, user, project_private, pointer, registration_private, url_registration_private, fork_private, component_private):

    #   test_cannot_access_registration_private_forks_list_unauthenticated
        res = app.get(url_registration_private, expect_errors=True)
        assert res.status_code == 401
        assert res.json['errors'][0]['detail'] == exceptions.NotAuthenticated.default_detail

    #   test_authenticated_contributor_can_access_registration_private_forks_list
        res = app.get('{}?embed=children&embed=node_links&embed=logs&embed=contributors&embed=forked_from'.format(url_registration_private), auth=user.auth)
        assert res.status_code == 200
        assert len(res.json['data']) == 1
        data = res.json['data'][0]
        assert data['attributes']['title'] == 'Fork of ' + project_private.title
        assert data['id'] == fork_private._id

        fork_contributors = data['embeds']['contributors']['data'][0]['embeds']['users']['data']
        assert fork_contributors['attributes']['family_name'] == user.family_name
        assert fork_contributors['id'] == user._id

        forked_children = data['embeds']['children']['data'][0]
        assert forked_children['id'] == registration_private.forks.first().get_nodes(is_node_link=False)[0]._id
        assert forked_children['attributes']['title'] == component_private.title

        forked_node_links = data['embeds']['node_links']['data'][0]['embeds']['target_node']['data']
        assert forked_node_links['id'] == pointer._id
        assert forked_node_links['attributes']['title'] == pointer.title
        assert data['attributes']['registration'] == False
        assert data['attributes']['fork'] is True

        expected_logs = list(registration_private.logs.values_list('action', flat=True))
        expected_logs.append(registration_private.nodes[0].logs.latest().action)
        expected_logs.append('node_forked')
        expected_logs.append('node_forked')

        forked_logs = data['embeds']['logs']['data']
        assert set(expected_logs) == set(log['attributes']['action'] for log in forked_logs)
        assert len(forked_logs) == len(expected_logs)

        forked_from = data['embeds']['forked_from']['data']
        assert forked_from['id'] == registration_private._id

    #   test_authenticated_non_contributor_cannot_access_registration_private_forks_list
        non_contributor = AuthUserFactory()

        res = app.get(url_registration_private, auth=non_contributor.auth, expect_errors=True)
        assert res.status_code == 403
        assert res.json['errors'][0]['detail'] == exceptions.PermissionDenied.default_detail

@pytest.mark.django_db
class TestRegistrationForkCreate:

    @pytest.fixture()
    def user_two(self):
        return AuthUserFactory()

    @pytest.fixture()
    def user_three(self):
        return AuthUserFactory()

    @pytest.fixture()
    def pointer_private(self, user_two):
        return ProjectFactory(creator=user_two)

    @pytest.fixture()
    def project_private(self, user, user_two, pointer_private):
        project_private = ProjectFactory(creator=user)
        project_private.add_pointer(pointer_private, auth=Auth(user_two), save=True)
        return project_private

    @pytest.fixture()
    def registration_private(self, user, project_private):
        return RegistrationFactory(creator=user, project=project_private)

    @pytest.fixture()
    def fork_data(self):
        return {
            'data': {
                'type': 'nodes'
            }
        }

    @pytest.fixture()
    def fork_data_with_title(self):
        return {
            'data': {
                'type': 'nodes',
                'attributes': {
                    'title': 'My Forked Project'
                }
            }
        }

    @pytest.fixture()
    def url_registration_private(self, registration_private):
        return '/{}registrations/{}/forks/'.format(API_BASE, registration_private._id)

    @pytest.fixture()
    def project_public(self, user):
        return ProjectFactory(is_public=True, creator=user)

    @pytest.fixture()
    def registration_public(self, user, project_public):
        return RegistrationFactory(creator=user, project=project_public, is_public=True)

    @pytest.fixture()
    def url_registration_public(self, registration_public):
        return '/{}registrations/{}/forks/'.format(API_BASE, registration_public._id)

    def test_create_fork_from_registration_public_with_new_title(self, app, user, registration_public, url_registration_public, fork_data_with_title):
        res = app.post_json_api(url_registration_public, fork_data_with_title, auth=user.auth)
        assert res.status_code == 201
        data = res.json['data']
        assert data['id'] == registration_public.forks.first()._id
        assert data['attributes']['title'] == fork_data_with_title['data']['attributes']['title']
        assert data['attributes']['registration'] == False
        assert data['attributes']['fork'] is True

    def test_create_fork_from_registration_private_with_new_title(self, app, user, registration_private, url_registration_private, fork_data_with_title):
        res = app.post_json_api(url_registration_private, fork_data_with_title, auth=user.auth)
        assert res.status_code == 201
        data = res.json['data']
        assert data['id'] == registration_private.forks.first()._id
        assert data['attributes']['title'] == fork_data_with_title['data']['attributes']['title']
        assert data['attributes']['registration'] == False
        assert data['attributes']['fork'] is True

    def test_can_fork_registration_public_logged_in(self, app, user_two, registration_public, url_registration_public, fork_data):
        res = app.post_json_api(url_registration_public, fork_data, auth=user_two.auth)
        assert res.status_code == 201
        data = res.json['data']
        assert data['id'] == registration_public.forks.first()._id
        assert data['attributes']['title'] == 'Fork of ' + registration_public.title
        assert data['attributes']['registration'] == False
        assert data['attributes']['fork'] is True

    def test_cannot_fork_registration_public_logged_out(self, app, url_registration_public, fork_data):
        res = app.post_json_api(url_registration_public, fork_data, expect_errors=True)
        assert res.status_code == 401
        assert res.json['errors'][0]['detail'] == exceptions.NotAuthenticated.default_detail

    def test_can_fork_registration_public_logged_in_contributor(self, app, user, registration_public, url_registration_public, fork_data):
        res = app.post_json_api(url_registration_public, fork_data, auth=user.auth)
        assert res.status_code == 201
        data = res.json['data']
        assert data['id'] == registration_public.forks.first()._id
        assert data['attributes']['title'] == 'Fork of ' + registration_public.title
        assert data['attributes']['registration'] == False
        assert data['attributes']['fork'] is True

    def test_cannot_fork_registration_private_logged_out(self, app, url_registration_private, fork_data):
        res = app.post_json_api(url_registration_private, fork_data, expect_errors=True)
        assert res.status_code == 401
        assert res.json['errors'][0]['detail'] == exceptions.NotAuthenticated.default_detail

    def test_cannot_fork_registration_private_logged_in_non_contributor(self, app, user_two, url_registration_private, fork_data):
        res = app.post_json_api(url_registration_private, fork_data, auth=user_two.auth, expect_errors=True)
        assert res.status_code == 403
        assert res.json['errors'][0]['detail'] == exceptions.PermissionDenied.default_detail

    def test_can_fork_registration_private_logged_in_contributor(self, app, user, registration_private, url_registration_private, fork_data):
        res = app.post_json_api('{}?embed=children&embed=node_links&embed=logs&embed=contributors&embed=forked_from'.format(url_registration_private), fork_data, auth=user.auth)
        assert res.status_code == 201

        data = res.json['data']
        assert data['attributes']['title'] == 'Fork of ' + registration_private.title
        assert data['attributes']['registration'] == False
        assert data['attributes']['fork'] is True

        fork_contributors = data['embeds']['contributors']['data'][0]['embeds']['users']['data']
        assert fork_contributors['attributes']['family_name'] == user.family_name
        assert fork_contributors['id'] == user._id

        forked_from = data['embeds']['forked_from']['data']
        assert forked_from['id'] == registration_private._id

    def test_fork_components_private_no_access(self, app, user_two, user_three, registration_public, url_registration_public, fork_data):
        url = '{}?embed=children'.format(url_registration_public)
        component_private = NodeFactory(parent=registration_public, creator=user_two, is_public=False)
        res = app.post_json_api(url, fork_data, auth=user_three.auth)
        assert res.status_code == 201
        # Private components that you do not have access to are not forked
        assert res.json['data']['embeds']['children']['links']['meta']['total'] == 0

    def test_fork_components_you_can_access(self, app, user, registration_private, url_registration_private, fork_data):
        url = '{}?embed=children'.format(url_registration_private)
        new_component = NodeFactory(parent=registration_private, creator=user)
        res = app.post_json_api(url, fork_data, auth=user.auth)
        assert res.status_code == 201
        assert res.json['data']['embeds']['children']['links']['meta']['total'] == 1
        assert res.json['data']['embeds']['children']['data'][0]['id'] == new_component.forks.first()._id

    def test_fork_private_node_links(self, app, user, url_registration_private, fork_data):

        url = '{}?embed=node_links'.format(url_registration_private)

        # Node link is forked, but shows up as a private node link
        res = app.post_json_api(url, fork_data, auth=user.auth)
        assert res.json['data']['embeds']['node_links']['data'][0]['embeds']['target_node']['errors'][0]['detail'] == exceptions.PermissionDenied.default_detail
        assert res.json['data']['embeds']['node_links']['links']['meta']['total'] == 1

    def test_fork_node_links_you_can_access(self, app, user, project_private, fork_data):
        pointer = ProjectFactory(creator=user)
        project_private.add_pointer(pointer, auth=Auth(user), save=True)

        new_registration = RegistrationFactory(project = project_private, creator=user)

        url = '/{}registrations/{}/forks/{}'.format(API_BASE, new_registration._id, '?embed=node_links')

        res = app.post_json_api(url, fork_data, auth=user.auth)
        assert res.json['data']['embeds']['node_links']['data'][1]['embeds']['target_node']['data']['id'] == pointer._id
        assert res.json['data']['embeds']['node_links']['links']['meta']['total'] == 2

    def test_cannot_fork_retractions(self, app, user, registration_private, fork_data):
        with mock.patch('osf.models.AbstractNode.update_search'):
            retraction = WithdrawnRegistrationFactory(registration=registration_private, user=user)
        url = '/{}registrations/{}/forks/{}'.format(API_BASE, registration_private._id, '?embed=forked_from')

        res = app.post_json_api(url, fork_data, auth=user.auth, expect_errors=True)
        assert res.status_code == 403
