DROP TABLE IF EXISTS arbiter_data.organization_invites;
DROP PROCEDURE accept_invite;
DROP PROCEDURE decline_invite;
DROP PROCEDURE create_invite;
DROP PROCEDURE list_user_invites;
DROP PROCEDURE create_user_if_not_exists;
DROP PROCEDURE user_exists;
DROP PROCEDURE get_current_user;
DELETE FROM arbiter_data.organizations where name = 'Public';
DELETE FROM arbiter_data.permissions WHERE object_type = 'invites';
DELETE FROM arbiter_data.roles WHERE name = 'Invite to Organization';
ALTER TABLE arbiter_data.permissions CHANGE COLUMN object_type object_type ENUM('sites', 'aggregates', 'cdf_forecasts', 'forecasts', 'observations', 'users', 'roles', 'permissions', 'reports') NOT NULL;
