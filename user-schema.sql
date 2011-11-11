-- TABLESPACE 
CREATE TABLESPACE &&TABLESPACE
    DATAFILE '/u02/oradata/banco/dat/security_dat_01.dbf' SIZE 100M AUTOEXTEND
    ON NEXT  100M MAXSIZE  5G EXTENT MANAGEMENT LOCAL SEGMENT
    SPACE MANAGEMENT  AUTO
/

-- USER 
CREATE USER &&USER_NAME identified by &&senha_user default tablespace &&TABLESPACE;

-- PRIVILEGES
ALTER USER &&USER_NAME QUOTA UNLIMITED ON &&TABLESPACE;
GRANT CONNECT TO &&USER_NAME;
GRANT CREATE PROCEDURE TO &&USER_NAME;
GRANT CREATE TABLE TO &&USER_NAME;
GRANT CREATE TRIGGER TO &&USER_NAME;
GRANT ADMINISTER DATABASE TRIGGER TO &&USER_NAME;
GRANT SELECT ON SYS.V_$SESSION TO &&USER_NAME;