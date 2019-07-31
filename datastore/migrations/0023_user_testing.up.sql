ALTER TABLE arbiter_data.permissions CHANGE COLUMN object_type object_type ENUM('sites', 'aggregates', 'cdf_forecasts', 'forecasts', 'observations', 'users', 'roles', 'permissions', 'reports', 'invites') NOT NULL;

SET @orgid = (SELECT UUID_TO_BIN(UUID(), 1));

INSERT INTO arbiter_data.organizations (name, id, accepted_tou) VALUES (
    'Public', @orgid, FALSE); -- not sure if accepted_tou = false

CREATE TABLE arbiter_data.organization_invites (
  id BINARY(16) NOT NULL DEFAULT (UUID_TO_BIN(UUID(), 1)),
  auth0_id VARCHAR(32) NOT NULL, -- the user to invite
  organization_id BINARY(16) NOT NULL, -- organization to invite user to

  PRIMARY KEY(id),
  KEY(auth0_id)
) ENGINE=INNODB ENCRYPTION='Y' ROW_FORMAT=COMPRESSED;

CREATE DEFINER = 'insert_rbac'@'localhost' PROCEDURE create_invite (
    IN auth0_id VARCHAR(32), IN invitee_auth0_id VARCHAR(32), IN organization_id VARCHAR(32))
COMMENT 'Create an invitation for a user to an organization'
MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    SET allowed = (SELECT user_can_create(auth0_id, 'invite'));
    IF allowed THEN
        INSERT INTO arbiter_data.invites (auth0_id, organization_id) VALUES (
            invitee_auth0_id, organization_id);
    END IF;
END;

CREATE DEFINER = 'insert_rbac'@'localhost' PROCEDURE accept_invite(
    IN strid VARCHAR(32), IN auth0_id VARCHAR(32))
COMMENT 'Accept an organization invite'
BEGIN
    DECLARE invitee_auth0id VARCHAR(32);
    DECLARE organization_id BINARY(16);
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    SELECT auth0_id, organization_id INTO invitee_auth0id, organization_id FROM arbiter_data.organization_invites WHERE id = (SELECT UUID_TO_BIN(strid));
    SET allowed = (SELECT auth0_id = invitee_auth0id);
    IF allowed THEN
        UPDATE arbiter_data.users SET organization_id = organization_id WHERE auth0_id = auth0_id;
    END IF;
END;


GRANT EXECUTE ON PROCEDURE arbiter_data.create_user TO 'apiuser'@'%';
GRANT EXECUTE ON PROCEDURE arbiter_data.accept_invite TO 'apiuser'@'%';
GRANT EXECUTE ON PROCEDURE arbiter_data.create_invite TO 'apiuser'@'%';

-- add permissions to the test user allowing them to invite
SET @orgid = (SELECT organization_id from arbiter_data.users WHERE auth0_id = 'auth0|5be343df7025406237820b85');
SET @create_invites = (SELECT UUID_TO_BIN(UUID(), 1));
INSERT INTO arbiter_data.permissions(id, description, organization_id, action, object_type, applies_to_all) VALUES (
    @create_invites, 'Invite users to test organizaiton', @orgid, 'create', 'invites', TRUE);
