-- 執行後檢查：catalog_count 各為 3500/5000/500/36/1088；
-- 可以看到所有舊入口對 authenticated 均返回 false。
select kind,count(*) as catalog_count from public.jiuli_secure_catalog group by kind order by kind;
select
 pg_catalog.has_function_privilege('authenticated','public.jiuli_secure_game(text,jsonb,uuid)','EXECUTE') as new_game_authorized,
 pg_catalog.has_function_privilege('anon','public.jiuli_secure_game(text,jsonb,uuid)','EXECUTE') as anonymous_blocked_should_be_false,
 pg_catalog.has_function_privilege('authenticated','public.jiuli_web_save(bigint,jsonb)','EXECUTE') as legacy_save_blocked_should_be_false;
select count(*) as migrated_players from public.jiuli_secure_accounts;

-- 自動化一定要檢查安全條件，不讓「有印出結果」被誤認為部署成功。
do $verify$
declare v_n bigint;
begin
 select count(*) into v_n from public.jiuli_secure_catalog where kind='fish';
 if v_n <> 3500 then raise exception 'CATALOG_FISH_COUNT_NOT_3500: %',v_n;end if;
 select count(*) into v_n from public.jiuli_secure_catalog where kind='seed';
 if v_n <> 5000 then raise exception 'CATALOG_SEED_COUNT_NOT_5000: %',v_n;end if;
 select count(*) into v_n from public.jiuli_secure_catalog where kind='recipe';
 if v_n <> 500 then raise exception 'CATALOG_RECIPE_COUNT_NOT_500: %',v_n;end if;
 select count(*) into v_n from public.jiuli_secure_catalog where kind='pet';
 if v_n <> 36 then raise exception 'CATALOG_PET_COUNT_NOT_36: %',v_n;end if;
 select count(*) into v_n from public.jiuli_secure_catalog where kind='crime';
 if v_n <> 1088 then raise exception 'CATALOG_CRIME_COUNT_NOT_1088: %',v_n;end if;
 if not pg_catalog.has_function_privilege('authenticated','public.jiuli_secure_game(text,jsonb,uuid)','EXECUTE')
  then raise exception 'AUTHENTICATED_GAME_RPC_DISABLED';end if;
 if pg_catalog.has_function_privilege('anon','public.jiuli_secure_game(text,jsonb,uuid)','EXECUTE')
  then raise exception 'ANONYMOUS_MUST_NOT_EXECUTE_GAME_RPC';end if;
 if pg_catalog.has_function_privilege('authenticated','public.jiuli_web_save(bigint,jsonb)','EXECUTE')
  then raise exception 'LEGACY_ARBITRARY_SAVE_MUST_BE_REVOKED';end if;
 if pg_catalog.to_regprocedure('public.jiuli_web_bank_action(text,bigint,text)') is not null then
  if pg_catalog.has_function_privilege('authenticated','public.jiuli_web_bank_action(text,bigint,text)','EXECUTE')
   then raise exception 'LEGACY_BANK_RPC_MUST_BE_REVOKED';end if;
 end if;
end;
$verify$;

-- WEB 1.5 好友系統權限檢查（任何失敗都中止 Actions）。
do $socialverify$
declare v_t text;
begin
 foreach v_t in array array['jiuli_social_friends','jiuli_social_team_invites','jiuli_social_gift_log','jiuli_social_interactions','jiuli_social_requests'] loop
  if pg_catalog.to_regclass('public.'||v_t) is null then raise exception 'SOCIAL_TABLE_MISSING: %',v_t;end if;
  if pg_catalog.has_table_privilege('authenticated','public.'||v_t,'INSERT')
   or pg_catalog.has_table_privilege('authenticated','public.'||v_t,'UPDATE')
   or pg_catalog.has_table_privilege('authenticated','public.'||v_t,'DELETE')
   or pg_catalog.has_table_privilege('authenticated','public.'||v_t,'SELECT') then
   raise exception 'SOCIAL_DIRECT_TABLE_ACCESS_DENIED: %',v_t;
  end if;
 end loop;
 if not pg_catalog.has_function_privilege('authenticated','public.jiuli_social_snapshot(text)','EXECUTE')
  then raise exception 'FRIEND_SNAPSHOT_DISABLED';end if;
 if not pg_catalog.has_function_privilege('authenticated','public.jiuli_social_action(text,text,text,text,integer,uuid)','EXECUTE')
  then raise exception 'FRIEND_ACTION_DISABLED';end if;
 if pg_catalog.has_function_privilege('anon','public.jiuli_social_action(text,text,text,text,integer,uuid)','EXECUTE')
  then raise exception 'ANON_FRIEND_ACTION_MUST_BE_BLOCKED';end if;
end;
$socialverify$;
