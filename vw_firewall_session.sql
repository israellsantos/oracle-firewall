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
