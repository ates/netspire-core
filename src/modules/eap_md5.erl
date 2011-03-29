-module(eap_md5).

-behaviour(gen_fsm).

%% API
-export([start_link/0, stop/0, challenge/1, verify/3]).

%% gen_fsm callbacks
-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
         terminate/3, code_change/4]).

%% FSM states
-export([idle/3, challenge/3, verify/2]).

-include("eap.hrl").

-define(TIMEOUT, 5000).
-define(CHALLENGE_LEN, 16).

-record(state, {challenge}).

start_link() ->
    gen_fsm:start_link({local, ?MODULE}, ?MODULE, [], []).

stop() ->
    gen_fsm:send_all_state_event(?MODULE, stop).

challenge(Packet) ->
    gen_fsm:sync_send_event(?MODULE, {challenge, Packet}).

verify(Ident, Packet, Password) ->
    gen_fsm:sync_send_event(?MODULE, {verify, Ident, Packet, Password}).

init([]) ->
    {ok, idle, #state{challenge = undefined}}.

%% MD5 Packet Format in EAP Type-Data
%% --- ------ ------ -- --- ---------
%%  0                   1                   2                   3
%%  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |  Value-Size   |  Value ...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% |  Name ...
%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

%% Compose EAP-MD5 Challenge packet
idle({challenge, Packet}, _From, State) ->
    Challenge = libeap:make_challenge(),
    MD5Packet = list_to_binary([<<?CHALLENGE_LEN:8>>, Challenge]),
    <<_:8, Ident:8, _:16, _:8, _/binary>> = Packet, % parsing EAP packet
    Length = 5 + byte_size(MD5Packet),
    EAPMessage = list_to_binary([<<?EAP_REQUEST:8, (Ident + 1):8, Length:16, ?EAP_MD5_CHALLENGE:8>>, MD5Packet]),
    Reply = [{"EAP-Message", EAPMessage}],
    NewState = State#state{challenge = Challenge},
    {reply, Reply, challenge, NewState};

idle(_Event, _From, State) ->
    {reply, {error, unknown_state}, idle, State}.

%% MD5(id + password + challenge_sent)
challenge({verify, Ident, Packet, Password}, _From, State) ->
    Hash = crypto:md5([Ident, Password, State#state.challenge]),
    <<_Size:8, ReqHash/binary>> = Packet,
    {reply, Hash =:= ReqHash, verify, State, ?TIMEOUT};

challenge(_Event, _From, State) ->
    {reply, {error, unknown_state}, idle, State}.

verify(timeout, _State) ->
    {stop, normal, _State}.

handle_event(stop, _StateName, State) ->
    {stop, normal, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {reply, ok, StateName, State}.

handle_info(_Info, StateName, State) ->
    {next_state, StateName, State}.

terminate(_Reason, _StateName, _State) ->
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

