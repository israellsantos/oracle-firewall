-- PR_FIREWALL_VALIDATE
-- TG_FIREWALL_LOGON
-- TB_FIREWALL_OPTION
-- TB_FIREWALL_RULE
-- TB_FIREWALL_RULE_LINE
-- TB_FIREWALL_LOG
 

-- TABLESPACE 
CREATE TABLESPACE SECURITY_DAT
    DATAFILE '/u02/oradata/tercd/dat/security_dat_01.dbf' SIZE 100M AUTOEXTEND 
    ON NEXT  100M MAXSIZE  5G EXTENT MANAGEMENT LOCAL SEGMENT 
    SPACE MANAGEMENT  AUTO
/

-- USER 
CREATE USER SECURITY identified by &&senha_user default tablespace &&TABLESPACE;
-- PRIVILEGES
ALTER USER SECURITY QUOTA UNLIMITED ON &&TABLESPACE;
GRANT CONNECT TO SECURITY;
GRANT CREATE PROCEDURE TO SECURITY;
GRANT CREATE TABLE TO SECURITY;
GRANT CREATE TRIGGER TO SECURITY;
GRANT ADMINISTER DATABASE TRIGGER TO SECURITY;
GRANT SELECT ON SYS.V_$SESSION TO SECURITY;
 
-- TABLES
CREATE TABLE TB_FIREWALL_CONFIG
(
 NAME        VARCHAR2(50) NOT NULL,
 DESCRIPTION VARCHAR2(100),
 ENABLED     VARCHAR2(1),
 CONSTRAINT CK_FWCONFIG_ENABLED CHECK (ENABLED IN ('Y','N'))
) TABLESPACE &&TABLESPACE
/

CREATE TABLE TB_FIREWALL_RULE
(
 PRIORITY    NUMBER NOT NULL ,
 RULE        VARCHAR2(40) NOT NULL ,
 DESCRIPTION VARCHAR2(500),
 ENABLED     VARCHAR2(1) DEFAULT 'N' NOT NULL
 CONSTRAINT  CK_FWRULE_ENABLED CHECK (ENABLED IN ('Y','N'))
) TABLESPACE &&TABLESPACE
/

CREATE TABLE TB_FIREWALL_RULE_LINE
(
 RULE        VARCHAR2(40) NOT NULL,
 LINE        NUMBER NOT NULL,
 USERNAME    VARCHAR2(30),
 OSUSER      VARCHAR2(30),
 MACHINE     VARCHAR2(64),
 MODULE      VARCHAR2(48),
 PROGRAM     VARCHAR2(48),
 ALLOW       VARCHAR2(1) NOT NULL,
 DT_BEGIN    DATE NOT NULL,
 DT_END      DATE,
 CONSTRAINT CK_FWRULELINE_ALLOW CHECK (ALLOW IN ('Y','N'))
) TABLESPACE &&TABLESPACE
/

CREATE TABLE TB_FIREWALL_LOG
(
 ID       NUMBER,
 RULE     VARCHAR2(40) NOT NULL,
 USERNAME VARCHAR2(30),
 OSUSER   VARCHAR2(30),
 MACHINE  VARCHAR2(64),
 PROGRAM  VARCHAR2(48),
 MODULE   VARCHAR2(48),
 EVENT    VARCHAR2(500),
 ALLOWED  VARCHAR2(1) NOT NULL,
 EM_DBA   VARCHAR2(1) NOT NULL,
 EM_USR   VARCHAR2(1) NOT NULL,
 CONSTRAINT CK_FWLOG_ALLOWED CHECK (ALLOWED IN ('Y','N')),
 CONSTRAINT CK_FWLOG_EM_DBA  CHECK (EM_DBA IN ('Y','N')),
 CONSTRAINT CK_FWLOG_EM_USR  CHECK (EM_USR IN ('Y','N'))
) TABLESPACE &&TABLESPACE
/

-- SEQUENCE

create sequence sq_firewall_log maxvalue 99999999999999999999;

-- VIEW

create or replace view vw_firewall_session as
select
   ses.sid                         sid,
   ses.audsid                      audsid,
   replace(ses.username,chr(0),'') username,
   replace(ses.osuser,chr(0),'')   osuser,
   replace(ses.machine,chr(0),'')  machine,
   replace(ses.module,chr(0),'')   module,
   replace(ses.program,chr(0),'')  program
from
   v$session ses
where 
   ses.username is not null;
/   

-- TRIGGER

create or replace trigger tg_firewall_logon after logon on database
begin

   pr_firewall_validate_logon;

end;
/

insert into tb_firewall_config(name,description,enabled) values ('SERVICE_STATUS','Status do Firewall','Y');
insert into tb_firewall_config(name,description,enabled) values ('SEND_MAIL_DBA','Envia e-mail para os DBAS','Y');
insert into tb_firewall_config(name,description,enabled) values ('SEND_MAIL_USER','Envia e-mail para o usuário','Y');
insert into tb_firewall_config(name,description,enabled) values ('LOG_ONLY','Loga acesso sem dropar a conexão','N');
insert into tb_firewall_config(name,description,enabled) values ('LOG_ACCESS_DENIED','Loga acesso negado','Y');
insert into tb_firewall_config(name,description,enabled) values ('LOG_ACCESS_ALLOWED','Loga acesso permitido','N');

