from random import shuffle


import pytest


@pytest.fixture()
def readall(cursor, new_organization, new_user, new_role, new_permission,
            new_site, new_forecast, new_observation):
    def make():
        org = new_organization()
        user = new_user(org=org)
        role = new_role(org=org)
        cursor.execute(
            'INSERT INTO user_role_mapping (user_id, role_id) VALUES (%s, %s)',
            (user['id'], role['id']))
        items = ['users', 'roles', 'permissions',
                 'forecasts', 'observations', 'sites']
        shuffle(items)
        perms = [new_permission('read', obj, True, org=org)
                 for obj in items]

        cursor.executemany(
            'INSERT INTO role_permission_mapping (role_id, permission_id)'
            ' VALUES (%s, %s)', [(role['id'], perm['id']) for perm in perms])
        sites = [new_site(org=org) for _ in range(2)]
        fx = [new_forecast(site=site) for site in sites for _ in range(2)]
        obs = [new_observation(site=site) for site in sites for _ in range(2)]
        return user, role, perms, sites, fx, obs
    return make


@pytest.fixture()
def twosets(readall):
    user, role, perms, sites, fx, obs = readall()
    dummy = readall()
    return user, role, perms, sites, fx, obs, dummy


@pytest.mark.parametrize('type_', ['permissions', 'sites', 'forecasts',
                                   'observations'])
def test_items_present(cursor, twosets, type_):
    cursor.execute(f'SELECT DISTINCT(organization_id) FROM {type_}')
    assert len(cursor.fetchall()) == 2


def test_list_users(dictcursor, twosets):
    user = twosets[0]
    authid = twosets[0]['auth0_id']
    dictcursor.callproc('list_users', (authid,))
    res = dictcursor.fetchall()[0]
    del res['created_at']
    del res['modified_at']
    assert res == user


def test_list_roles(dictcursor, twosets):
    authid = twosets[0]['auth0_id']
    role = twosets[1]
    dictcursor.callproc('list_roles', (authid,))
    res = dictcursor.fetchall()[0]
    del res['created_at']
    del res['modified_at']
    assert res == role


def test_list_permissions(dictcursor, twosets):
    authid = twosets[0]['auth0_id']
    perms = twosets[2]
    dictcursor.callproc('list_permissions', (authid,))
    res = dictcursor.fetchall()
    for r in res:
        del r['created_at']
    assert res == perms


def test_list_sites(dictcursor, twosets):
    authid = twosets[0]['auth0_id']
    sites = twosets[3]
    dictcursor.callproc('list_sites', (authid,))
    res = dictcursor.fetchall()
    assert [site['id'] for site in sites] == [r['id'] for r in res]
    assert (
        (set(res[0].keys()) - set(('created_at', 'modified_at'))) ==
        set(sites[0].keys()))


def test_list_forecasts(dictcursor, twosets):
    authid = twosets[0]['auth0_id']
    fxs = twosets[4]
    dictcursor.callproc('list_forecasts', (authid,))
    res = dictcursor.fetchall()
    assert [fx['id'] for fx in fxs] == [r['id'] for r in res]
    assert (
        (set(res[0].keys()) - set(('created_at', 'modified_at'))) ==
        set(fxs[0].keys()))


def test_list_observations(dictcursor, twosets):
    authid = twosets[0]['auth0_id']
    obs = twosets[5]
    dictcursor.callproc('list_observations', (authid,))
    res = dictcursor.fetchall()
    assert [ob['id'] for ob in obs] == [r['id'] for r in res]
    assert (
        (set(res[0].keys()) - set(('created_at', 'modified_at'))) ==
        set(obs[0].keys()))