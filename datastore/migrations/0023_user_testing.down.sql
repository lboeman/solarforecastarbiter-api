DROP TABLE IF EXISTS arbiter_data.organization_invites;
DROP PROCEDURE accept_invite;
DROP PROCEDURE create_invite;
DELETE FROM arbiter_data.organizations where name = 'Public';
