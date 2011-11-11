create or replace trigger tg_firewall_logon after logon on database
begin

   pr_firewall_validate_logon;

end;
/
