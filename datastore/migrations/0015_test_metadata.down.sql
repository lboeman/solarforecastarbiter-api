DELETE FROM arbiter_data.organizations WHERE id = UUID_TO_BIN('876abd2e-9fe1-11e9-9e44-64006a511e6f', 1);
DELETE FROM arbiter_data.organizations WHERE id = UUID_TO_BIN('b76ab62e-4fe1-11e9-9e44-64006a511e6f', 1);
DROP USER 'apiuser'@'%';
