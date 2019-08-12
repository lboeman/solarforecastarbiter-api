ALTER TABLE arbiter_data.permissions CHANGE COLUMN object_type object_type ENUM('sites', 'aggregates', 'cdf_forecasts', 'forecasts', 'observations', 'users', 'roles', 'permissions', 'reports', 'invites') NOT NULL;

-- Create an organization and default role for public users to access the framework
SET @orgid = (SELECT UUID_TO_BIN(UUID(), 1));
INSERT INTO arbiter_data.organizations (name, id, accepted_tou) VALUES (
    'Public', @orgid, FALSE);


CREATE TABLE arbiter_data.organization_invites (
  id BINARY(16) NOT NULL DEFAULT (UUID_TO_BIN(UUID(), 1)),
  inviter_id VARCHAR(32) NOT NULL,
  invitee_id VARCHAR(32) NOT NULL,
  organization_id BINARY(16) NOT NULL, -- organization to invite user to

  PRIMARY KEY(id),
  KEY(invitee_id)
) ENGINE=INNODB ENCRYPTION='Y' ROW_FORMAT=COMPRESSED;


CREATE DEFINER = 'select_rbac'@'localhost' PROCEDURE user_exists (IN auth0id VARCHAR(32))
COMMENT 'Returns 1 if a user exists with the given auth0 id'
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    SELECT 1 FROM arbiter_data.users WHERE auth0_id = auth0id;
END;


CREATE DEFINER = 'insert_rbac'@'localhost' PROCEDURE create_user_if_not_exists(IN auth0id VARCHAR(32))
COMMENT 'Inserts a new user and adds then to the Public org, and read reference role'
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE orgid BINARY(16);
    DECLARE userid BINARY(16);
    DECLARE refroleid BINARY(16);
    SET userid = UUID_TO_BIN(UUID(), 1);
    SET orgid = (SELECT id FROM arbiter_data.organizations WHERE name = "Public");
    SET refroleid = (SELECT id FROM arbiter_data.roles WHERE name = 'Read Reference Data');
    IF (SELECT NOT EXISTS(SELECT 1 FROM arbiter_data.users WHERE auth0_id = auth0id)) THEN
        INSERT INTO arbiter_data.users (id, auth0_id, organization_id) VALUES (
            userid, auth0id, orgid); 
        INSERT INTO arbiter_data.user_role_mapping (user_id, role_id) VALUES (userid, refroleid);
    END IF;
END;


CREATE DEFINER = 'insert_rbac'@'localhost' PROCEDURE create_invite (
    IN auth0id VARCHAR(32), IN invitee_auth0id VARCHAR(32))
COMMENT 'Create an invitation for a user to an organization'
MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    DECLARE permissible BOOLEAN DEFAULT FALSE;
    DECLARE userexists BOOLEAN DEFAULT FALSE;
    DECLARE organizationid BINARY(16);
    SET permissible = (SELECT user_can_create(auth0id, 'invites'));
    SET userexists = (SELECT EXISTS(SELECT 1 FROM arbiter_data.users where auth0_id = invitee_auth0id));
    SELECT concat('permissible is ', permissible);
    SELECT concat('exists is ', userexists);
    SET organizationid = get_user_organization(auth0id);
    SET allowed = (SELECT userexists AND permissible);
    IF allowed THEN
        INSERT INTO arbiter_data.organization_invites (inviter_id, invitee_id, organization_id) VALUES (
            auth0id, invitee_auth0id, organizationid);
    ELSE
        SIGNAL SQLSTATE '42000' SET MESSAGE_TEXT = 'Access denied to user on "create_invite"',
        MYSQL_ERRNO = 1142;
    END IF;
END;

CREATE DEFINER = 'select_rbac'@'localhost' PROCEDURE list_user_invites(
    IN auth0id VARCHAR(32))
COMMENT 'Read values of invites for a user.'
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    SELECT BIN_TO_UUID(organization_invites.id, 1) as invite_id, BIN_TO_UUID(organizations.id,1) as organization_id, organizations.name
    FROM arbiter_data.organization_invites
            INNER JOIN
         arbiter_data.organizations ON organization_invites.organization_id = organizations.id
    WHERE arbiter_data.organization_invites.invitee_id = auth0id; 
END;


CREATE DEFINER = 'insert_rbac'@'localhost' PROCEDURE accept_invite(
    IN auth0id VARCHAR(32), IN strid VARCHAR(36))
COMMENT 'Accept an organization invite'
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    DECLARE invitee VARCHAR(32);
    DECLARE inviteid BINARY(16);
    DECLARE organizationid BINARY(16);
    SET inviteid = (SELECT UUID_TO_BIN(strid, 1));
    SELECT invitee_id, organization_id INTO invitee, organizationid  FROM arbiter_data.organization_invites WHERE id = inviteid;
    SET allowed = (SELECT invitee = auth0id);
    SELECT concat('orgid is ', BIN_TO_UUID(organizationid, 1));
    SELECT concat('invitee is ', invitee);
    IF allowed THEN
        UPDATE arbiter_data.users SET organization_id = organizationid WHERE auth0_id = auth0id;
        DELETE FROM arbiter_data.organization_invites WHERE id = inviteid;
    ELSE
        SIGNAL SQLSTATE '42000' SET MESSAGE_TEXT = 'Access denied to user on "accept_invite"',
        MYSQL_ERRNO = 1142;
    END IF;
END;

CREATE DEFINER = 'insert_rbac'@'localhost' PROCEDURE decline_invite(
    IN auth0id VARCHAR(32), IN strid VARCHAR(36))
COMMENT 'Accept an organization invite'
BEGIN
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    DECLARE invitee VARCHAR(32);
    DECLARE inviteid BINARY(16);
    DECLARE organizationid BINARY(16);
    SET inviteid = (SELECT UUID_TO_BIN(strid, 1));
    SELECT invitee_id, organization_id INTO invitee, organizationid  FROM arbiter_data.organization_invites WHERE id = inviteid;
    SET allowed = (SELECT invitee = auth0id);
    IF allowed THEN
        DELETE FROM arbiter_data.organization_invites WHERE id = inviteid;
    ELSE
        SIGNAL SQLSTATE '42000' SET MESSAGE_TEXT = 'Access denied to user on "decline_invite"',
        MYSQL_ERRNO = 1142;
    END IF;
END;

CREATE DEFINER = 'select_rbac'@'localhost' PROCEDURE get_current_user(
    IN auth0id VARCHAR(32))
COMMENT 'Return the current users information'
BEGIN
    SELECT BIN_TO_UUID(id, 1) as user_id, auth0_id, BIN_TO_UUID(organization_id, 1) as organization_id, get_organization_name(organization_id) as organization FROM arbiter_data.users WHERE auth0_id = auth0id;   
END;

GRANT SELECT, UPDATE ON arbiter_data.users to 'insert_rbac'@'localhost';
GRANT SELECT ON arbiter_data.roles to 'insert_rbac'@'localhost';
GRANT SELECT ON arbiter_data.organizations to 'insert_rbac'@'localhost';
GRANT UPDATE, DELETE, INSERT, SELECT ON arbiter_data.organization_invites to 'insert_rbac'@'localhost';

GRANT SELECT ON arbiter_data.organizations TO 'select_rbac'@'localhost';
GRANT SELECT ON arbiter_data.organization_invites TO 'select_rbac'@'localhost';

GRANT EXECUTE ON PROCEDURE arbiter_data.get_current_user TO 'select_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.get_current_user TO 'apiuser'@'%';

GRANT EXECUTE ON PROCEDURE arbiter_data.user_exists TO 'select_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.user_exists TO 'insert_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.user_exists TO 'apiuser'@'%';

GRANT EXECUTE ON PROCEDURE arbiter_data.create_user_if_not_exists TO 'insert_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.create_user_if_not_exists TO 'apiuser'@'%';

GRANT EXECUTE ON PROCEDURE arbiter_data.accept_invite TO 'insert_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.accept_invite TO 'apiuser'@'%';

GRANT EXECUTE ON PROCEDURE arbiter_data.create_invite TO 'insert_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.create_invite TO 'apiuser'@'%';

GRANT EXECUTE ON PROCEDURE arbiter_data.list_user_invites TO 'select_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.list_user_invites TO 'apiuser'@'%';


-- add permissions to the test user allowing them to invite
SET @orgid = (SELECT organization_id from arbiter_data.users WHERE auth0_id = 'auth0|5be343df7025406237820b85');
SET @test_invite_perm = (SELECT UUID_TO_BIN(UUID(), 1));
SET @test_invite_role = (SELECT UUID_TO_BIN(UUID(), 1));
INSERT INTO arbiter_data.permissions(id, description, organization_id, action, object_type, applies_to_all) VALUES (
    @test_invite_perm, 'Invite users to test organizaiton', @orgid, 'create', 'invites', TRUE);

INSERT INTO arbiter_data.roles (name, description, id, organization_id) VALUES (
    'Invite to Organization', 'Allowed to invite users to the organizations', @test_invite_role, @orgid);
INSERT INTO arbiter_data.role_permission_mapping (role_id, permission_id) VALUES (
    @test_invite_role, @test_invite_perm);
SET @test_user = (SELECT id FROM arbiter_data.users WHERE auth0_id = 'auth0|5be343df7025406237820b85');
INSERT INTO arbiter_data.user_role_mapping (user_id, role_id) VALUES (@test_user, @test_invite_role);
