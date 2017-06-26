import pytest

from api.base.settings.defaults import API_BASE
from framework.auth.core import Auth
from website.util import disconnected_from_listeners
from website.project.signals import contributor_removed
from osf_tests.factories import (
    NodeFactory,
    AuthUserFactory,
    RegistrationFactory
)

@pytest.fixture()
def user():
    return AuthUserFactory()

@pytest.mark.django_db
class TestNodeRelationshipNodeLinks:

    @pytest.fixture()
    def contributor(self):
        return AuthUserFactory()

    @pytest.fixture()
    def auth(self, user):
        return Auth(user)

    @pytest.fixture()
    def node_private(self, user):
        return NodeFactory(creator=user)

    @pytest.fixture()
    def node_admin(self, user):
        return NodeFactory(creator=user)

    @pytest.fixture()
    def node_other(self):
        return NodeFactory()

    @pytest.fixture()
    def node_public(self):
        return NodeFactory(is_public=True)

    @pytest.fixture()
    def node_source(self, user, auth, node_private, node_admin):
        node_source = NodeFactory(creator=user)
        node_source.add_pointer(node_private, auth=auth)
        node_source.add_pointer(node_admin, auth=auth)
        return node_source

    @pytest.fixture()
    def node_contributor(self, user, contributor):
        node_contributor = NodeFactory(creator=contributor)
        node_contributor.add_contributor(user, auth=Auth(contributor))
        node_contributor.save()
        return node_contributor

    @pytest.fixture()
    def node_public_source(self, contributor, node_private, node_public):
        node_public_source = NodeFactory(is_public=True, creator=contributor)
        node_public_source.add_pointer(node_private, auth=Auth(contributor))
        node_public_source.add_pointer(node_public, auth=Auth(contributor))
        node_public_source.save()
        return node_public_source

    @pytest.fixture()
    def registration_node_public_source(self, node_public_source, contributor):
        return RegistrationFactory(project=node_public_source, is_public=True, creator=contributor)

    @pytest.fixture()
    def registration_node_source(self, user, node_source):
        return RegistrationFactory(project=node_source, creator=user)

    @pytest.fixture()
    def url(self, registration_node_source):
        return '/{}registrations/{}/relationships/linked_nodes/'.format(API_BASE, registration_node_source._id)

    @pytest.fixture()
    def url_public(self, registration_node_public_source):
        return '/{}registrations/{}/relationships/linked_nodes/'.format(API_BASE, registration_node_public_source._id)

    @pytest.fixture()
    def payload(self, node_admin):
        def payload(node_ids=None):
            node_ids = node_ids or [node_admin._id]
            return {'data': [{'type': 'linked_nodes', 'id': node_id} for node_id in node_ids]}
        return payload

    def test_node_relationship_node_links(self, app, user, url, url_public, registration_node_source, node_private, node_admin, node_public, node_contributor, node_other, payload):

    #   get_relationship_linked_nodes
        res = app.get(url, auth=user.auth)

        assert res.status_code == 200
        assert registration_node_source.linked_nodes_self_url in res.json['links']['self']
        assert registration_node_source.linked_nodes_related_url in res.json['links']['html']
        assert node_private._id in [e['id'] for e in res.json['data']]

    #   get_linked_nodes_related_counts
        res = app.get(
            '/{}registrations/{}/?related_counts=linked_nodes'.format(API_BASE, registration_node_source._id),
            auth=user.auth
        )

        assert res.json['data']['relationships']['linked_nodes']['links']['related']['meta']['count'] == 2

    #   get_public_relationship_linked_nodes_logged_out
        res = app.get(url_public)

        assert res.status_code == 200
        assert len(res.json['data']) == 1
        assert node_public._id in [e['id'] for e in res.json['data']]

    #   get_public_relationship_linked_nodes_logged_in
        res = app.get(url_public, auth=user.auth)

        assert res.status_code == 200
        assert len(res.json['data']) == 2

    #   get_private_relationship_linked_nodes_logged_out
        res = app.get(url, expect_errors=True)

        assert res.status_code == 401

    #   post_contributing_node
        res = app.post_json_api(
            url, payload([node_contributor._id]),
            auth=user.auth, expect_errors=True
        )

        assert res.status_code == 405

    #   post_node_public
        res = app.post_json_api(
            url, payload([node_public._id]),
            auth=user.auth, expect_errors=True
        )

        assert res.status_code == 405

    #   post_node_private
        res = app.post_json_api(
            url, payload([node_other._id]),
            auth=user.auth,
            expect_errors=True
        )

        assert res.status_code == 405

        res = app.get(
            url, auth=user.auth
        )

        ids = [data['id'] for data in res.json['data']]
        assert node_other._id not in ids
        assert node_private._id in ids

    #   post_mixed_nodes
        res = app.post_json_api(
            url, payload([node_other._id, node_contributor._id]),
            auth=user.auth,
            expect_errors=True
        )

        assert res.status_code == 405

        res = app.get(
            url, auth=user.auth
        )

        ids = [data['id'] for data in res.json['data']]
        assert node_other._id not in ids
        assert node_contributor._id not in ids
        assert node_private._id in ids

    #   post_node_already_linked
        res = app.post_json_api(
            url, payload([node_private._id]),
            auth=user.auth, expect_errors=True
        )

        assert res.status_code == 405

    #   put_contributing_node
        res = app.put_json_api(
            url, payload([node_contributor._id]),
            auth=user.auth, expect_errors=True
        )

        assert res.status_code == 405

    #   put_node_private
        res = app.put_json_api(
            url, payload([node_other._id]),
            auth=user.auth,
            expect_errors=True
        )

        assert res.status_code == 405

        res = app.get(
            url, auth=user.auth
        )

        ids = [data['id'] for data in res.json['data']]
        assert node_other._id not in ids
        assert node_private._id in ids

    #   put_mixed_nodes
        res = app.put_json_api(
            url, payload([node_other._id, node_contributor._id]),
            auth=user.auth, expect_errors=True
        )

        assert res.status_code == 405

        res = app.get(
            url, auth=user.auth
        )

        ids = [data['id'] for data in res.json['data']]
        assert node_other._id not in ids
        assert node_contributor._id not in ids
        assert node_private._id in ids

    #   delete_with_put_empty_array
        new_payload = payload()
        new_payload['data'].pop()
        res = app.put_json_api(
            url, new_payload, auth=user.auth, expect_errors=True
        )
        assert res.status_code == 405

    #   delete_one
        res = app.delete_json_api(
            url, payload([node_private._id]),
            auth=user.auth, expect_errors=True
        )
        assert res.status_code == 405

        res = app.get(url, auth=user.auth)

        ids = [data['id'] for data in res.json['data']]
        assert node_admin._id in ids
        assert node_private._id in ids

    #   delete_multiple

        res = app.delete_json_api(
            url, payload([node_private._id, node_admin._id]),
            auth=user.auth, expect_errors=True
        )
        assert res.status_code == 405

        res = app.get(url, auth=user.auth)
        assert len(res.json['data']) == 2

    #   delete_not_present
        number_of_links = registration_node_source.linked_nodes.count()
        res = app.delete_json_api(
            url, payload([node_other._id]),
            auth=user.auth, expect_errors=True
        )
        assert res.status_code == 405

        res = app.get(
            url, auth=user.auth
        )
        assert len(res.json['data']) == number_of_links

    #   node_doesnt_exist
        res = app.post_json_api(
            url, payload(['aquarela']),
            auth=user.auth,
            expect_errors=True
        )

        assert res.status_code == 405

    #   type_mistyped
        res = app.post_json_api(
            url,
            {
                'data': [{'type': 'not_linked_nodes', 'id': node_contributor._id}]
            },
            auth=user.auth,
            expect_errors=True
        )

        assert res.status_code == 405

    #   creates_public_linked_node_relationship_logged_out
        res = app.post_json_api(
                url_public, payload([node_public._id]),
                expect_errors=True
        )

        assert res.status_code == 401

    #   creates_public_linked_node_relationship_logged_in
        res = app.post_json_api(
                url_public, payload([node_public._id]),
                auth=user.auth, expect_errors=True
        )

        assert res.status_code == 405

    #   creates_private_linked_node_relationship_logged_out
        res = app.post_json_api(
                url, payload([node_other._id]),
                expect_errors=True
        )

        assert res.status_code == 401

    #   put_node_public_relationships_logged_out
        res = app.put_json_api(
                url_public, payload([node_public._id]),
                expect_errors=True
        )

        assert res.status_code == 401

    #   put_node_public_relationships_logged_in
        res = app.put_json_api(
                url_public, payload([node_private._id]),
                auth=user.auth, expect_errors=True
        )

        assert res.status_code == 405

    #   delete_node_public_relationships_logged_out
        res = app.delete_json_api(
            url_public, payload([node_public._id]),
            expect_errors=True
        )

        assert res.status_code == 401

    #   delete_node_public_relationships_logged_in
        res = app.delete_json_api(
                url_public, payload([node_private._id]),
                auth=user.auth, expect_errors=True
        )

        assert res.status_code == 405

@pytest.mark.django_db
class TestNodeLinkedNodes:

    @pytest.fixture()
    def auth(self, user):
        return Auth(user)

    @pytest.fixture()
    def node_private_one(self, user):
        return NodeFactory(creator=user)

    @pytest.fixture()
    def node_private_two(self, user):
        return NodeFactory(creator=user)

    @pytest.fixture()
    def node_source(self, user, auth, node_private_one, node_private_two, node_public):
        node_source = NodeFactory(creator=user)
        node_source.add_pointer(node_private_one, auth=auth)
        node_source.add_pointer(node_private_two, auth=auth)
        node_source.add_pointer(node_public, auth=auth)
        node_source.save()
        return node_source

    @pytest.fixture()
    def node_public(self, user):
        return NodeFactory(is_public=True, creator=user)

    @pytest.fixture()
    def registration_node_source(self, user, node_source):
        return RegistrationFactory(project=node_source, creator=user)

    @pytest.fixture()
    def url(self, registration_node_source):
        return '/{}registrations/{}/linked_nodes/'.format(API_BASE, registration_node_source._id)

    @pytest.fixture()
    def node_ids(self, registration_node_source):
        return list(registration_node_source.nodes_pointer.values_list('guids___id', flat=True))

    def test_linked_nodes_returns_everything(self, app, user, url, node_ids):
        res = app.get(url, auth=user.auth)

        assert res.status_code == 200
        nodes_returned = [linked_node['id'] for linked_node in res.json['data']]
        assert len(nodes_returned) == len(node_ids)

        for node_id in node_ids:
            assert node_id in nodes_returned

    def test_linked_nodes_only_return_viewable_nodes(self, app, auth, node_private_one, node_private_two, node_public, node_ids):
        user = AuthUserFactory()
        new_registration_node_source = NodeFactory(creator=user)
        node_private_one.add_contributor(user, auth=auth, save=True)
        node_private_two.add_contributor(user, auth=auth, save=True)
        node_public.add_contributor(user, auth=auth, save=True)
        new_registration_node_source.add_pointer(node_private_one, auth=Auth(user))
        new_registration_node_source.add_pointer(node_private_two, auth=Auth(user))
        new_registration_node_source.add_pointer(node_public, auth=Auth(user))
        new_registration_node_source.save()
        new_linking_registration = RegistrationFactory(project=new_registration_node_source, creator=user)

        res = app.get(
            '/{}registrations/{}/linked_nodes/'.format(API_BASE, new_linking_registration._id),
            auth=user.auth
        )

        assert res.status_code == 200
        nodes_returned = [linked_node['id'] for linked_node in res.json['data']]
        assert len(nodes_returned) == len(node_ids)

        for node_id in node_ids:
            assert node_id in nodes_returned

        # Disconnect contributor_removed so that we don't check in files
        # We can remove this when StoredFileNode is implemented in osf-models
        with disconnected_from_listeners(contributor_removed):
            node_private_two.remove_contributor(user, auth=auth)
            node_public.remove_contributor(user, auth=auth)

        res = app.get(
            '/{}registrations/{}/linked_nodes/'.format(API_BASE, new_linking_registration._id),
            auth=user.auth
        )
        nodes_returned = [linked_node['id'] for linked_node in res.json['data']]
        assert len(nodes_returned) == len(node_ids) - 1

        assert node_private_one._id in nodes_returned
        assert node_public._id in nodes_returned
        assert node_private_two._id not in nodes_returned

    def test_linked_nodes_doesnt_return_deleted_nodes(self, app, user, url, node_private_one, node_private_two, node_public, node_ids):
        node_private_one.is_deleted = True
        node_private_one.save()
        res = app.get(url, auth=user.auth)

        assert res.status_code == 200
        nodes_returned = [linked_node['id'] for linked_node in res.json['data']]
        assert len(nodes_returned) == len(node_ids) - 1

        assert node_private_one._id not in nodes_returned
        assert node_private_two._id in nodes_returned
        assert node_public._id in nodes_returned

    def test_attempt_to_return_linked_nodes_logged_out(self, app, url):
        res = app.get(url, auth=None, expect_errors=True)

        assert res.status_code == 401
