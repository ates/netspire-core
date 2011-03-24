-module(csv).

-export([read/1]).

read(String) ->
    read(String, []).

%%
%% Internal functions
%%
read([], Acc) ->
    lists:reverse(Acc);
read(String, []) ->
    {Line, Rest} = read_line(String),
    read(Rest, [Line]);
read([10|String], Acc) ->
    {Line, Rest} = read_line(String),
    read(Rest, [Line|Acc]);
read([13,10|String], Acc) ->
    {Line, Rest} = read_line(String),
    read(Rest, [Line|Acc]).
   
add_spaces(0, String) -> String;
add_spaces(Count, String) ->
    add_spaces(Count - 1, [$ |String]).

read_item([34|T]) ->
    read_item_quoted(T, []);
read_item(Other) ->
    read_item(Other, 0, []).

read_item([32|T], 0, []) ->
    read_item(T, 0, []);
read_item([9|T], 0, []) ->
    read_item(T, 0, []);
read_item([10|T], _SpaceCount, Acc) ->
    {lists:reverse(Acc), [10|T]};
read_item([13,10|T], _SpaceCount, Acc) ->
    {lists:reverse(Acc), [13,10|T]};
read_item([$,|T], _SpaceCount, Acc) ->
    {lists:reverse(Acc), [$,|T]};
read_item([], _SpaceCount, Acc) ->
    {lists:reverse(Acc), []};
read_item([9|T], SpaceCount, Acc) ->
    read_item(T, SpaceCount + 1, Acc);
read_item([32|T], SpaceCount, Acc) ->
    read_item(T, SpaceCount + 1, Acc);
read_item([C|T], SpaceCount, Acc) ->
    read_item(T, 0, [C|add_spaces(SpaceCount, Acc)]).

read_item_quoted([34,34|T], Acc) ->
    read_item_quoted(T, [34|Acc]);
read_item_quoted([34|T], Acc) ->
    {lists:reverse(Acc), T};
read_item_quoted([C|T], Acc) ->
    read_item_quoted(T, [C|Acc]).

read_line(String) -> read_line(String,[]).

read_line([10|T], Acc) ->
    {lists:reverse(Acc), [10|T]};
read_line([13,10|T], Acc) ->
    {lists:reverse(Acc), [13|T]};
read_line([], Acc) ->
    {lists:reverse(Acc), []};
read_line(String, []) ->
    {Item, Rest} = read_item(String), read_line(Rest, [Item]);
read_line([$,|String], Acc) ->
    {Item, Rest} = read_item(String), read_line(Rest, [Item|Acc]).
