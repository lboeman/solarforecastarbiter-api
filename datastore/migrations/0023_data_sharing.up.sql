/*
 * add grant and revoke actions to permissions table
 */
ALTER TABLE arbiter_data.permissions CHANGE COLUMN action action ENUM('create', 'read', 'update',  'delete', 'read_values', 'write_values', 'delete_values', 'grant', 'revoke') NOT NULL;

/*
 * RBAC helper functions to limit sharing of roles outside the organization.
 */
CREATE DEFINER = 'select_rbac'@'localhost' FUNCTION role_granted_to_external_users(roleid BINARY(16))
RETURNS BOOLEAN
COMMENT 'Determines if a role has been granted to a user outside the organizaiton'
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE orgid BINARY(16);
    SET orgid = get_object_organization(roleid, 'roles');
    RETURN (SELECT EXISTS(
        SELECT 1 FROM arbiter_data.user_role_mapping
            WHERE role_id = roleid
           AND user_id IN (
                SELECT id FROM arbiter_data.users
                WHERE organization_id != orgid
            )
        )
    );
END;
GRANT EXECUTE ON FUNCTION arbiter_data.role_granted_to_external_users TO 'select_rbac'@'localhost';
GRANT EXECUTE ON FUNCTION arbiter_data.role_granted_to_external_users TO 'insert_rbac'@'localhost';


CREATE DEFINER = 'select_rbac'@'localhost' FUNCTION rbac_permissions_check(permid BINARY(16))
RETURNS BOOLEAN
COMMENT 'Determines if the permission controls actions on rbac objects'
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    RETURN (SELECT EXISTS (
        SELECT 1 FROM arbiter_data.permissions
            WHERE id = permid AND object_type IN ('roles', 'permissions', 'users')
        )
    );
END;
GRANT EXECUTE ON FUNCTION arbiter_data.rbac_permissions_check TO 'select_rbac'@'localhost';
GRANT EXECUTE ON FUNCTION arbiter_data.rbac_permissions_check TO 'insert_rbac'@'localhost';


CREATE DEFINER = 'select_rbac'@'localhost' FUNCTION does_user_exist(auth0id VARCHAR(32))
RETURNS BOOLEAN
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    RETURN (SELECT EXISTS(SELECT 1 from arbiter_data.users where auth0_id = auth0id));
END;
GRANT EXECUTE ON FUNCTION arbiter_data.does_user_exist to 'select_rbac'@'localhost';


CREATE DEFINER = 'select_rbac'@'localhost' FUNCTION get_reference_role_id()
RETURNS BINARY(16)
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    RETURN (SELECT id
            FROM arbiter_data.roles
            WHERE name = 'Read Reference Data'
                AND organization_id = get_organization_id('Reference'));
END;
GRANT EXECUTE ON FUNCTION arbiter_data.get_reference_role_id TO 'select_rbac'@'localhost';


CREATE DEFINER = 'select_rbac'@'localhost' FUNCTION role_contains_rbac_permissions(roleid BINARY(16))
RETURNS BOOLEAN
COMMENT 'Determines if a role contains rbac object permissions'
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    RETURN (SELECT EXISTS (
        SELECT 1 FROM arbiter_data.role_permission_mapping
            WHERE role_id = roleid
            AND rbac_permissions_check(permission_id)
        )
    );
END;
GRANT EXECUTE ON FUNCTION arbiter_data.role_contains_rbac_permissions TO 'select_rbac'@'localhost';
GRANT EXECUTE ON FUNCTION arbiter_data.role_contains_rbac_permissions TO 'insert_rbac'@'localhost';


/*
 * Drop and redefine add_role_to_user to depend on the 'grant' role action
 */
DROP PROCEDURE arbiter_data.add_role_to_user;

CREATE DEFINER = 'insert_rbac'@'localhost' PROCEDURE add_role_to_user (
    IN auth0id VARCHAR(32), IN user_id CHAR(36), IN role_id CHAR(36))
COMMENT 'Add a role to a user'
MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
    
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    DECLARE roleid BINARY(16);
    DECLARE userid BINARY(16);
    DECLARE role_org BINARY(16);
    DECLARE caller_org BINARY(16);
    DECLARE grantee_org BINARY(16);

    SET roleid = UUID_TO_BIN(role_id, 1);
    SET role_org = get_object_organization(roleid, 'roles');
    SET caller_org = get_user_organization(auth0id);
    SET userid = UUID_TO_BIN(user_id, 1);
    SET grantee_org = get_object_organization(userid, 'users');
    SET allowed = can_user_perform_action(auth0id, roleid, 'grant') AND
        caller_org = role_org AND
        grantee_org IS NOT NULL;
    IF allowed THEN
        IF caller_org = grantee_org THEN
            -- If caller and grantee have same org, add the role to the user
            INSERT INTO arbiter_data.user_role_mapping (user_id, role_id) VALUES (
                userid, roleid);
        ELSE
            IF role_contains_rbac_permissions(roleid) THEN
                /* If caller and grantee do not have same org, and the role contains
                 * rbac permissions, return an error.
                 */
                SIGNAL SQLSTATE '42000' SET MESSAGE_TEXT = 'Cannot share administrative role outside organization',
                MYSQL_ERRNO = 1142;
            ELSE
                INSERT INTO arbiter_data.user_role_mapping (user_id, role_id) VALUES (
                    userid, roleid);
            END IF;
        END IF;
    ELSE
        SIGNAL SQLSTATE '42000' SET MESSAGE_TEXT = 'Access denied to user on "add role to user"',
        MYSQL_ERRNO = 1142;
    END IF;
END;

GRANT EXECUTE ON PROCEDURE arbiter_data.add_role_to_user TO 'insert_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.add_role_to_user TO 'apiuser'@'%';


/*
 * Drop delete_role_from user and redefine using the 'revoke' role permission
 */
DROP PROCEDURE remove_role_from_user;

-- define delete role from user
CREATE DEFINER = 'delete_rbac'@'localhost' PROCEDURE remove_role_from_user (
    IN auth0id VARCHAR(32), IN role_strid CHAR(36), IN user_strid CHAR(36))
COMMENT 'Remove a role from a user'
BEGIN
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    DECLARE roleid BINARY(16);
    DECLARE role_org BINARY(16);
    DECLARE userid BINARY(16);
    DECLARE caller_org BINARY(16);
    SET caller_org = get_user_organization(auth0id);
    SET roleid = UUID_TO_BIN(role_strid, 1);
    SET role_org = get_object_organization(roleid, 'roles');
    SET userid = UUID_TO_BIN(user_strid, 1);
    -- calling user must have permission to revoke role
    -- calling user and role must be in the same organization
    SET allowed = can_user_perform_action(auth0id, roleid, 'revoke') AND
         (caller_org = role_org);
    IF allowed THEN
        DELETE FROM arbiter_data.user_role_mapping WHERE user_id = userid AND role_id = roleid;
    ELSE
        SIGNAL SQLSTATE '42000' SET MESSAGE_TEXT = 'Access denied to user on "remove role from user"',
        MYSQL_ERRNO = 1142;
    END IF;
END;
GRANT EXECUTE ON PROCEDURE arbiter_data.remove_role_from_user TO 'delete_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.remove_role_from_user TO 'apiuser'@'%';
GRANT EXECUTE ON FUNCTION arbiter_data.get_object_organization TO 'delete_rbac'@'localhost';


/*
 * Define the Unaffiliated Organization and the basic user role to read
 * reference data. Add a test user for external shares.
 */
SET @orgid = (SELECT UUID_TO_BIN(UUID(), 1));
INSERT INTO arbiter_data.organizations (name, id, accepted_tou) VALUES (
        'Unaffiliated', @orgid, FALSE);

INSERT INTO arbiter_data.users (id, auth0_id, organization_id) VALUES(
    UUID_TO_BIN('ef026b76-c049-11e9-9c7e-0242ac120002', 1), 'auth0|test_public', @orgid);


/*
 * If the calling user does not exist, create a new user and add them to the
 * database under the 'unaffiliated' org grant them the Reference reading role
 */
CREATE DEFINER = 'insert_rbac'@'localhost' PROCEDURE create_user_if_not_exists(IN auth0id VARCHAR(32))
COMMENT 'Inserts a new user and adds then to the Public org, and read reference role'
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE userid BINARY(16);
    SET userid = UUID_TO_BIN(UUID(), 1);
    IF NOT does_user_exist(auth0id) THEN
        INSERT INTO arbiter_data.users (id, auth0_id, organization_id) VALUES (
            userid, auth0id, get_organization_id('Unaffiliated'));
        INSERT INTO arbiter_data.user_role_mapping (user_id, role_id) VALUES (
            userid, get_reference_role_id());
    END IF;
END;
GRANT EXECUTE ON PROCEDURE arbiter_data.create_user_if_not_exists TO 'insert_rbac'@'localhost';
GRANT EXECUTE ON FUNCTION arbiter_data.does_user_exist TO 'insert_rbac'@'localhost';
GRANT EXECUTE ON FUNCTION arbiter_data.get_reference_role_id TO 'insert_rbac'@'localhost';

GRANT EXECUTE ON PROCEDURE arbiter_data.create_user_if_not_exists TO 'apiuser'@'%';


/*
 * Procedure to get current user metadata (auth0id, organization name and id)
 */
CREATE DEFINER = 'select_rbac'@'localhost' PROCEDURE get_current_user_info (
    IN auth0id VARCHAR(32))
COMMENT 'Read the identifying information for the current user.'
BEGIN
    SELECT get_organization_name(organization_id) as organization,
        BIN_TO_UUID(organization_id, 1) as organization_id,
        BIN_TO_UUID(id, 1) as user_id, auth0_id
    FROM arbiter_data.users WHERE auth0_id = auth0id;
END;
GRANT EXECUTE ON PROCEDURE arbiter_data.get_current_user_info TO 'select_rbac'@'localhost';
GRANT EXECUTE ON FUNCTION arbiter_data.get_organization_name TO 'select_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.get_current_user_info TO 'apiuser'@'%';


CREATE DEFINER = 'select_rbac'@'localhost' FUNCTION get_users_of_role(
    roleid BINARY(16))
RETURNS JSON
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE jsonout JSON;
    SET jsonout = (SELECT JSON_OBJECTAGG(BIN_TO_UUID(user_id, 1), created_at)
        FROM arbiter_data.user_role_mapping WHERE role_id = roleid
        GROUP BY role_id);
    IF jsonout IS NOT NULL THEN
        RETURN jsonout;
    ELSE
        RETURN JSON_OBJECT();
    END IF;
END;
GRANT EXECUTE ON FUNCTION arbiter_data.get_users_of_role TO 'select_rbac'@'localhost';


DROP PROCEDURE arbiter_data.read_role;
CREATE DEFINER = 'select_rbac'@'localhost' PROCEDURE read_role(
   IN auth0id VARCHAR(32), IN strid CHAR(36))
COMMENT 'Read role metadata'
MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    DECLARE binid BINARY(16);
    SET binid = UUID_TO_BIN(strid, 1);
    SET allowed = can_user_perform_action(auth0id, binid, 'read');
    IF allowed THEN
       SELECT name, description, BIN_TO_UUID(id, 1) as role_id,
           get_organization_name(organization_id) as organization, created_at, modified_at,
           get_permissions_of_role(id) as permissions,
		   get_users_of_role(id) as users
       FROM arbiter_data.roles WHERE id = binid;
    ELSE
        SIGNAL SQLSTATE '42000' SET MESSAGE_TEXT = 'Access denied to user on "read role"',
        MYSQL_ERRNO = 1142;
    END IF;
END;
GRANT EXECUTE ON PROCEDURE arbiter_data.read_role TO 'select_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.read_role TO 'apiuser'@'%';


CREATE DEFINER = 'select_rbac'@'localhost' PROCEDURE user_exists (
    IN auth0id VARCHAR(32))
COMMENT 'Detect if a User exists'
BEGIN
    SELECT does_user_exist(auth0id);
END;
GRANT EXECUTE ON PROCEDURE arbiter_data.user_exists TO 'select_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.user_exists TO 'apiuser'@'%';


/*
 * Drop and redefine add_permission_to_role to limit ability to add
 * rbac permissions to roles assigned to external users
 */
DROP PROCEDURE add_permission_to_role;

CREATE DEFINER = 'insert_rbac'@'localhost' PROCEDURE add_permission_to_role (
    IN auth0id VARCHAR(32), IN role_id CHAR(36), IN permission_id CHAR(36))
COMMENT 'Add an permission to the role permission mapping table'
MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE allowed BOOLEAN DEFAULT FALSE;
    DECLARE roleid BINARY(16);
    DECLARE permid BINARY(16);
    DECLARE userorg BINARY(16);
    SET userorg = get_user_organization(auth0id);
    SET roleid = UUID_TO_BIN(role_id, 1); 
    SET permid = UUID_TO_BIN(permission_id, 1); 
    -- Check if user has update permission on the role and that
    -- role and permission have same organization
    SET allowed = can_user_perform_action(auth0id, roleid, 'update') AND 
        userorg = get_object_organization(permid, 'permissions') AND 
        userorg = get_object_organization(roleid, 'roles');
    IF allowed IS NOT NULL AND allowed THEN
        -- Don't insert an rbac permission when a role is granted externally 
        IF rbac_permissions_check(permid) AND role_granted_to_external_users(roleid) THEN
            SIGNAL SQLSTATE '42000' SET MESSAGE_TEXT = 'Cannot add administrative permissions to role of external users',
            MYSQL_ERRNO = 1142;
        ELSE
            INSERT INTO arbiter_data.role_permission_mapping (
                role_id, permission_id) VALUES (roleid, permid);
        END IF;
    ELSE
        SIGNAL SQLSTATE '42000' SET MESSAGE_TEXT = 'Access denied to user on "add permission to role"',
        MYSQL_ERRNO = 1142;
    END IF; 
END;

GRANT EXECUTE ON PROCEDURE arbiter_data.add_permission_to_role TO 'insert_rbac'@'localhost';
GRANT EXECUTE ON PROCEDURE arbiter_data.add_permission_to_role TO 'apiuser'@'%';
