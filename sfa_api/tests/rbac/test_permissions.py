import pytest

from sfa_api.conftest import PERMISSION
from sfa_api.conftest import BASE_URL


def test_list_permissions(api):
    perms = api.get('/permissions/', BASE_URL)
    assert perms.status_code == 200
    assert len(perms.json) > 0


def test_list_permissions_no_perms(api, remove_perms_from_current_role):
    remove_perms_from_current_role('read', 'permissions')
    perms = api.get('/permissions/', BASE_URL)
    assert perms.status_code == 200
    assert len(perms.json) == 0


def test_create_permission(api):
    create_perm = api.post('/permissions/', BASE_URL, json=PERMISSION)
    assert create_perm.status_code == 201
    perm_id = create_perm.data.decode('utf-8')
    get_perm = api.get(f'/permissions/{perm_id}', BASE_URL)
    assert get_perm.status_code == 200
    perm = get_perm.json
    assert perm['description'] == PERMISSION['description']
    assert perm['applies_to_all'] == PERMISSION['applies_to_all']
    assert perm['object_type'] == PERMISSION['object_type']
    assert perm['action'] == PERMISSION['action']
    assert type(perm['objects']) == dict
    assert perm['organization'] == 'Organization 1'


def test_create_permission_no_perms(api, remove_perms_from_current_role):
    remove_perms_from_current_role('create', 'permissions')
    failed_create = api.post('/permission/', BASE_URL, json=PERMISSION)
    assert failed_create.status_code == 404


def perm(action, object_type, description, applies_to_all):
    return {
        'action': action,
        'object_type': object_type,
        'description': description,
        'applies_to_all': applies_to_all,
    }


@pytest.mark.parametrize('perm,error', [
    (perm('nope', 'roles', 'role perm', True),
        '{"action":["Must be one of: create, read, update, delete, read_values, write_values, delete_values, grant, revoke."]}'),  # noqa: E501
    (perm('create', 'role', 'role perm', True),
     '{"object_type":["Must be one of: sites, aggregates, forecasts, observations, users, roles, permissions, cdf_forecasts, reports."]}'),  # noqa: E501
    (perm('create', 'roles', 'role perm', 5),
     '{"applies_to_all":["Not a valid boolean."]}'),
])
def test_create_permission_invalid_json(api, perm, error):
    failed_create = api.post('/permissions/', BASE_URL, json=perm)
    assert failed_create.status_code == 400
    assert failed_create.get_data(as_text=True) == f'{{"errors":{error}}}\n'


def test_get_permission(api, new_perm):
    perm_id = new_perm()
    get_perm = api.get(f'/permissions/{perm_id}', BASE_URL)
    assert get_perm.status_code == 200
    response = get_perm.get_json()
    assert response['created_at'].endswith('+00:00')


def test_get_permission_no_perms(
        api, remove_perms_from_current_role, new_perm):
    perm_id = new_perm()
    remove_perms_from_current_role('read', 'permissions')
    get_fail = api.get(f'/permissions/{perm_id}', BASE_URL)
    assert get_fail.status_code == 404


def test_delete_permission(api, new_perm):
    perm_id = new_perm()
    delete_perm = api.delete(f'/permissions/{perm_id}', BASE_URL)
    assert delete_perm.status_code == 204
    assert api.get(f'/permissions/{perm_id}', BASE_URL).status_code == 404


def test_delete_permission_no_perms(
        api, new_perm, remove_perms_from_current_role):
    perm_id = new_perm()
    remove_perms_from_current_role('delete', 'permissions')
    delete_fail = api.delete(f'/permissions/{perm_id}', BASE_URL)
    assert delete_fail.status_code == 404


def test_add_object_to_permission(api, new_perm, new_observation):
    perm_id = new_perm()
    new_obs = new_observation()
    add_to_perm = api.post(f'/permissions/{perm_id}/objects/{new_obs}',
                           BASE_URL)
    assert add_to_perm.status_code == 204
    get_perm = api.get(f'/permissions/{perm_id}', BASE_URL)
    perm = get_perm.json
    objects_on_perm = perm['objects']
    assert new_obs in objects_on_perm.keys()


def test_add_object_to_permission_object_already_exists(
        api, new_perm, new_observation):
    perm_id = new_perm()
    new_obs = new_observation()
    add_to_perm = api.post(f'/permissions/{perm_id}/objects/{new_obs}',
                           BASE_URL)
    assert add_to_perm.status_code == 204
    add_to_perm_failure = api.post(f'/permissions/{perm_id}/objects/{new_obs}',
                                   BASE_URL)
    assert add_to_perm_failure.status_code == 400
    response = add_to_perm_failure.json['errors']
    assert response['permission'] == ['Permission already acts upon object.']


def test_add_object_to_permission_no_permission_object_already_exists(
        api, new_perm, new_observation, remove_perms_from_current_role):
    perm_id = new_perm()
    new_obs = new_observation()
    add_to_perm = api.post(f'/permissions/{perm_id}/objects/{new_obs}',
                           BASE_URL)
    assert add_to_perm.status_code == 204
    remove_perms_from_current_role('update', 'permissions')
    add_to_perm_failure = api.post(f'/permissions/{perm_id}/objects/{new_obs}',
                                   BASE_URL)
    assert add_to_perm_failure.status_code == 404


@pytest.mark.parametrize('action,object_type', [
    ('update', 'permissions'),
    ('read', 'observations'),
])
def test_add_object_to_permission_no_perms(
        api, new_perm, new_observation, remove_perms_from_current_role,
        action, object_type):
    perm_id = new_perm()
    obs_id = new_observation()
    remove_perms_from_current_role(action, object_type)
    add_to_perm = api.post(f'/permissions/{perm_id}/objects/{obs_id}',
                           BASE_URL)
    assert add_to_perm.status_code == 404


def test_remove_object_from_permission(api, new_perm, new_observation):
    perm_id = new_perm()
    obs_id = new_observation()
    add_object = api.post(f'/permissions/{perm_id}/objects/{obs_id}',
                          BASE_URL)
    assert add_object.status_code == 204
    delete_object = api.delete(f'/permissions/{perm_id}/objects/{obs_id}',
                               BASE_URL)
    assert delete_object.status_code == 204
    get_perm = api.get(f'/permissions/{perm_id}', BASE_URL)
    perm = get_perm.json
    objects_on_perm = perm['objects']
    assert obs_id not in objects_on_perm.keys()


def test_remove_object_from_permission_perm_dne(
        api, missing_id, new_observation):
    obs_id = new_observation()
    remove_object = api.delete(f'/permissions/{missing_id}/objects/{obs_id}',
                               BASE_URL)
    assert remove_object.status_code == 404


def test_remove_object_from_permission_object_dne(
        api, new_perm, missing_id, new_observation):
    # test that objects list is not altered even though 204 is returned
    perm_id = new_perm()
    new_obs = new_observation()
    add_to_perm = api.post(f'/permissions/{perm_id}/objects/{new_obs}',
                           BASE_URL)
    assert add_to_perm.status_code == 204
    get_perm = api.get(f'/permissions/{perm_id}', BASE_URL)
    perm = get_perm.json
    objects_on_perm = perm['objects']

    remove_object = api.delete(f'/permissions/{perm_id}/objects/{missing_id}',
                               BASE_URL)
    assert remove_object.status_code == 204

    get_perm = api.get(f'/permissions/{perm_id}', BASE_URL)
    perm = get_perm.json
    new_objects_on_perm = perm['objects']
    assert objects_on_perm == new_objects_on_perm


def test_remove_object_from_permission_object_applies_to_all(
        api, new_perm,  new_observation):
    # test that objects list is not altered even though 204 is returned
    perm_id = new_perm(applies_to_all=True)
    new_obs = new_observation()
    # without adding to perm assert observation read allowed
    get_perm = api.get(f'/permissions/{perm_id}', BASE_URL)
    perm = get_perm.json
    objects_on_perm = perm['objects']
    assert new_obs in objects_on_perm
    remove_object = api.delete(f'/permissions/{perm_id}/objects/{new_obs}',
                               BASE_URL)
    assert remove_object.status_code == 404


@pytest.mark.parametrize('action,object_type', [
    ('update', 'permissions'),
])
def test_remove_object_from_permission_no_perms(
        api, new_perm, new_observation, remove_perms_from_current_role,
        action, object_type):
    perm_id = new_perm()
    obs_id = new_observation()
    add_object = api.post(f'/permissions/{perm_id}/objects/{obs_id}',
                          BASE_URL)
    assert add_object.status_code == 204
    remove_perms_from_current_role(action, object_type)
    delete_object = api.delete(f'/permissions/{perm_id}/objects/{obs_id}',
                               BASE_URL)
    assert delete_object.status_code == 404


@pytest.mark.parametrize('desc,error', [
    ("<script>console.log();</script>", 'Invalid characters in string.'),
    ("a"*65, 'Longer than maximum length 64.'),
    ("!", 'Invalid characters in string.'),
])
def test_create_permission_invalid_description(api, desc, error):
    new_perm = perm('read', 'observation', desc, True)
    create_perm = api.post('/permissions/', BASE_URL, json=new_perm)
    assert create_perm.status_code == 400
    errors = create_perm.json['errors']
    assert errors['description'] == [error]
