-module(radius_util).

-export([verify_requirements/2]).

%% Check module requirements
verify_requirements(Request, Module) when is_atom(Module) ->
    case gen_module:get_option(Module, requirements) of
        undefined -> true;
        Rules ->
            match_requirements(Request, Rules)
    end.

%%
%% Internal functions
%%
match_requirements(_, []) -> true;
match_requirements(Request, [{Attr, Value}|Tail]) ->
    case radius:attribute_value(Attr, Request) of
        undefined -> false;
        RequestValue ->
            case match_pair(RequestValue, Value) of
                ok -> match_requirements(Request, Tail);
                _ -> false
            end
    end.

match_pair(_, []) ->
    nomatch;
match_pair(Value, [H|T]) ->
    case re:run(Value, H, [{capture, none}]) of
        match -> ok;
        _ ->
            match_pair(Value, T)
    end.
