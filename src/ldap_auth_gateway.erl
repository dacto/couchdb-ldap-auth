%%%-------------------------------------------------------------------
%%% @author dmoore
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%%%% @end
%%% Created : 08. Oct 2013 10:21 PM
%%%-------------------------------------------------------------------
-module(ldap_auth_gateway).
-author("dmoore").

-include_lib("eldap/include/eldap.hrl").
-include("couch_db.hrl").

%% API
-export([connect/0, authenticate/3, get_user_dn/2, get_group_memberships/2]).

-import(ldap_auth_config, [get_config/1]).

authenticate(LdapConnection, User, Password) ->
  case get_user_dn(LdapConnection, User) of
    {error, _} = Error -> Error;
    {ok, UserDN} ->
      % attempt to connect as UserDN and if it doesn't throw, immediately disconnect.
      case connect(UserDN, Password) of
        {ok, UserLdapConnection} ->
          eldap:close(UserLdapConnection),
          { ok, UserDN };
        {error, _} = Error ->
          ?LOG_INFO("Could authenticate user ~p with given password.", [User]),
          Error
      end
  end.

get_user_dn(LdapConnection, User) when User =/= <<"">>, User =/= "" ->
  [UserDNMapAttr] = get_config(["UserDNMapAttr"]),

  case query(LdapConnection, "person", eldap:equalityMatch(UserDNMapAttr, User)) of
    [] ->
      ?LOG_INFO("Could not find user with ~s = ~p to authenticate.", [UserDNMapAttr, User]),
      { error, invalid_credentials };
    [#eldap_entry{ object_name = UserDN } | _] ->
      {ok, UserDN}
  end.

connect() ->
  case catch get_config(["SearchUserDN", "SearchUserPassword"]) of
    {config_key_not_found, _} -> connect("", "");
    [SearchUserDN, SearchUserPassword] -> connect(SearchUserDN, SearchUserPassword)
  end.

connect(DN, Password) ->
  [LdapServers, UseSsl] = get_config(["LdapServers", "UseSsl"]),
  LdapServerList = re:split(LdapServers, "\\s*,\\s*", [{return, list}]),
  Args = [{ssl, list_to_atom(UseSsl)}] ++
    (case get_config(["Port"]) of
      {config_key_not_found, _} -> [];
      [Port] -> [{port, list_to_integer(Port)}]
    end) ++
    (case {DN, Password} of
      {"", ""} -> [{anon_auth, true}];
      _ -> []
    end), % ++ ([{log, fun(_,S,A) -> io:format(S,A) end}]),
  ?LOG_DEBUG("Opening LDAP connection: ~p/~p", [LdapServerList, Args]),
  case eldap:open(LdapServerList, Args) of
    {error, Reason} -> throw({ ldap_connection_error, Reason });
    {ok, LdapConnection} ->
      case eldap:simple_bind(LdapConnection, DN, Password) of
        {error, _} ->
          eldap:close(LdapConnection),
          { error, invalid_credentials };
        ok -> { ok, LdapConnection }
      end
  end.

query(LdapConnection, Type, Filter) ->
  [BaseDN] = get_config(["BaseDN"]),
  TypedFilter = eldap:'and'([eldap:equalityMatch("objectClass", Type), Filter]),
  case eldap:search(LdapConnection, [{ base, BaseDN }, { filter, TypedFilter }]) of
    {error, Reason} -> throw({search, Reason});
    {ok, #eldap_search_result{ entries = Result }} -> Result
  end.

get_group_memberships(LdapConnection, UserDN) ->
  Memberships = get_group_memberships(LdapConnection, sets:new(), UserDN),
  [ R || {_, R} <- sets:to_list(Memberships)].

get_group_memberships(LdapConnection, Memberships, DN) ->
  [GroupDNMapAttr] = get_config(["GroupDNMapAttr"]),
  case query(LdapConnection, "group", eldap:equalityMatch("member", DN)) of
    [] -> Memberships;
    Entries ->
      ParentGroupDNs = [
        case element(2, lists:keyfind(GroupDNMapAttr, 1, X#eldap_entry.attributes)) of
          [Value|_] -> {X#eldap_entry.object_name, Value};
          _ -> throw({no_value})
        end || X <- Entries
      ],
      S = sets:subtract(sets:from_list(ParentGroupDNs), Memberships),
      case sets:size(S) of
        0 -> Memberships;
        _ -> sets:fold(fun ({N, _}, P) -> get_group_memberships(LdapConnection, P, N) end, sets:union(Memberships, S), S)
      end
  end.
