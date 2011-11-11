create or replace
procedure pr_firewall_validate_logon as

   cursor cRules is
      select
         rl.rule,
         rl.allow,
         ses.username,
         ses.osuser,
         ses.machine,
         ses.module,
         ses.program
      from 
         tb_firewall_rule r,
         tb_firewall_rule_line rl,
         vw_firewall_session ses
      where 
         r.enabled = 'Y'
         and
         r.rule = rl.rule
         and
         ses.audsid = sys_context('USERENV','SESSIONID')
         and
         ses.username = nvl(rl.username,ses.username)
         and
         ses.osuser   = nvl(rl.osuser,ses.osuser)
         and
         ses.machine  like nvl(rl.machine,ses.machine)
         and
         ses.module   like nvl(rl.module,ses.module)
         and
         ses.program  like nvl(rl.program,ses.program)
         and
         sysdate between rl.dt_begin and nvl(rl.dt_end,sysdate + 1)
      order by
         r.priority;

   vMsgAccessDenied varchar2(500);
   
   procedure pr_log_access(iRule varchar2,
                           iUsername varchar2,
                           iOsuser varchar2,
                           iMachine varchar2,
                           iProgram varchar2,
                           iModule varchar2,
                           iEvent varchar2,
                           iAllowed varchar2,
                           iEm_dba varchar2,
                           iEm_usr varchar2) is

                           
      
      -- necessário para fazer o commit dentro da trigger
      pragma autonomous_transaction;
   
   begin

      insert into tb_firewall_log (
         id,
         rule,
         username,
         osuser,
         machine,
         program,
         module,
         event,
         allowed,
         em_dba,
         em_usr
      )
      values (
         sq_firewall_log.nextval,
         iRule,
         iUsername,
         iOsuser,
         iMachine,
         iProgram,
         iModule,
         iEvent,
         iAllowed,
         iEm_dba,
         iEm_usr
      );      
      
      commit;
   
   end;
   
   function fn_get_config(iOption varchar2) return varchar2 is
      vEnabled varchar2(1);
   begin
      
      select
         conf.enabled
      into
         vEnabled
      from
         tb_firewall_config conf
      where
         conf.name = iOption;

      return vEnabled;
   end;
   
begin

   -- Verifica se o serviço está ativo
   if fn_get_config('SERVICE_STATUS') = 'N' then
      return;
   end if;

   for x in cRules loop
      
      -- Verifica acesso

      if (x.allow = 'Y') then

         -- ACESSO PERMITIDO
         
         if fn_get_config('LOG_ACCESS_ALLOWED') = 'Y' then
            -- Registra acesso permitido no Log
            pr_log_access(x.rule,x.username,x.osuser,x.machine,x.program,x.module,'Acesso Permitido',x.allow,'N','N');
         end if;

         return;

      elsif (x.allow = 'N') then
      
         -- ACESSO NEGADO
         
         -- envia email dba
         -- envia email user

         if fn_get_config('LOG_ACCESS_DENIED') = 'Y' then
            -- Registra acesso negado no Log
            pr_log_access(x.rule,x.username,x.osuser,x.machine,x.program,x.module,'Acesso Negado',x.allow,'N','N');
         end if;
         
         if fn_get_config('LOG_ONLY') = 'N' then

            vMsgAccessDenied :='ACESSO NÃO AUTORIZADO!!!' || chr(10) ||
                               'Usuario BD: ' || x.username || chr(10) ||
                               'Usuario SO: ' || x.osuser   || chr(10) ||
                               'Estacão:    ' || x.machine  || chr(10) ||
                               'Módulo:     ' || x.module   || chr(10) ||
                               'Programa:   ' || x.program  || chr(10) || chr(10) ||
                               'Caso você não concorde com isso, entre em contato com a CGTI via chamado.' || chr(10) ||
                               'Esse incidente será reportado.';

            -- Encerra conexão
            raise_application_error(-20001,vMsgAccessDenied);
            
         end if;
      
      end if;
      
   end loop;

end;
