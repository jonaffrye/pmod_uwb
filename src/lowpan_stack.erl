-module(lowpan_stack). 
-behaviour(gen_statem).

%-include("lowpan_stack.hrl").
%-include("ieee802154.hrl").
-include("../src/mac_frame.hrl").

% API
-export([start_link/1, start/1, stop_link/0, stop/0]).

% gen_statem callbacks
-export([init/1, callback_mode/0,terminate/3,code_change/4]).
-export([idle_state/3]).
-export([snd_pckt/1]).
-export([rcv_frame/0]).
-export([input_callback/4]).

-export([pckt_tx_state/3, frame_rx_state/3]).

%--- API --------------------------------------------------------------------------------

%% @doc Starts the 6lowpan statck and creates a link
%% @end

-spec start_link(Params::#{}) -> {ok, pid()} | {error, any()}.
start_link(Params) -> 
    gen_statem:start_link({local, ?MODULE}, ?MODULE, Params, []).

% Starts statem
start(Params) -> 
    gen_statem:start({local, ?MODULE}, ?MODULE, Params, []),
    
    io:format("lowpan stack launched").
stop_link() ->
    gen_statem:stop(?MODULE).

% Stops statem
stop() -> io:format("lowpan stack stopped"), gen_statem:stop(?MODULE).

% Send an IPv6 packet
-spec snd_pckt(Ipv6Pckt :: bitstring()) -> ok.
snd_pckt(Ipv6Pckt)->
    % gen_statem:call(StateName, Event)
    gen_statem:call(?MODULE, {pckt_tx, Ipv6Pckt}). 

% Receive a processed packet
rcv_frame()->
    gen_statem:call(?MODULE, {frame_rx}). 

%get_panId()->
%    gen_statem:call(?MODULE, {get, pan_id}). 

%get_mac_address()->
%    gen_statem:call(?MODULE, {get, add}). 


% --- Callbacks -----------

init(Params) ->
    init_ets_callback_table(node()), % initialize callback table on mock_phy_net
    SrcMacAdd = maps:get(src_mac_addr, Params), 
    DstMacAdd = maps:get(dest_mac_addr,Params),
    Data = #{src_mac_addr => SrcMacAdd, dest_mac_addr => DstMacAdd},
    DatagramMap = maps:new(),
    %Data = #{
    %    Params => Params,
    %    datagram_map => DatagramMap
    %},
    {ok, idle_state, Data}. % idle is the initital state of our system 
    % Data represent all of the data we want to associate with the state machine


% --- state -----------

%--------------------------------------------------------
% In the Idle state, when a pckt_tx event is received 
% compress the header, fragment the pckt and transmit it
% to the mac layer via ieee802154
% state_name(EventType, EventContent, Data)
% EventType specify the type of event
% EventContent is the previous state
% Data, the current data of the syst
%--------------------------------------------------------
idle_state({call, From}, {pckt_tx, Ipv6Pckt}, Data) ->
    {next_state, pckt_tx_state, Data, [{next_event, internal, {pckt_tx, idle_state, Ipv6Pckt, From}}]};
    %{next_state, pckt_tx_state, Data#{fragments=>Ipv6Pckt}};%, [{reply, From, ok, Data}]};


% Idle call for frame reception
idle_state({call, From}, {frame_rx}, Data) ->
    {next_state, frame_rx_state, Data, [{next_event, internal, {frame_rx, idle_state, From}}]}.
    %{next_state, frame_rx_state, Data}.


% --- Internal state -----------
% Handling packet transmission state
pckt_tx_state(_EventType, {pckt_tx, IdleState, Ipv6Pckt, From}, Data = #{src_mac_addr := SrcMacAddress, dest_mac_addr := DstMacAddress}) ->
    %io:format("DstMacAddress ~p~n", [DstMacAddress]),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt),
    {_, _, _, _, _,_, _, DestAddress, Payload} = lowpan:get_ipv6_pckt_info(Ipv6Pckt),
    DestMacAddress = lowpan:get_mac_add(DestAddress),
    io:format("DestMacAddress: ~p~n",[DestMacAddress]),
   
    CompressedPacket = <<CompressedHeader/binary, Payload/binary>>,
    Fragments = lowpan:fragment_ipv6_packet(CompressedPacket),

    

    Response = lists:foreach(fun({Header, Datas})->
        io:format("Fragment: ~p~n",[<<Header/binary,Datas/binary>>]),
                        ieee802154:transmission({#frame_control{src_addr_mode = ?EXTENDED, dest_addr_mode = ?EXTENDED}, 
                                                #mac_header{src_addr = SrcMacAddress, dest_addr = DestMacAddress},
                                                <<Header/binary,Datas/binary>>})
                        end, Fragments),
    {next_state, IdleState, Data#{fragments => Fragments}, [{reply, From, Response}]}.
       

% State for handling packet receiving
frame_rx_state(_EventType, {frame_rx, _, From}, State) ->
    Rx_on = ieee802154:rx_on(), % ensures continuous reception 
    case Rx_on of 
        ok ->
            io:format("Rx_on activated on node: ~p~n",[node()]),
            StartTime = erlang:monotonic_time(millisecond),
            get_new_frame(From, State, 0, StartTime);
        {error, E} ->
            {next_state, idle_state, State, [{reply, From, {error, E}}]}
    end.

get_new_frame(From, State, PrevNbRxFrames, StartTime) ->
    [{_, NbRxFrames}] = ets:lookup(callback_table, nb_rx_frames), % get current NbRxFrames
    CurrentTime = erlang:monotonic_time(millisecond),
    MaxTime = 5000,

    case NbRxFrames of
        PrevNbRxFrames when CurrentTime - StartTime > MaxTime -> % nothing new received and timeput of 5s 
            {next_state, idle_state, State, [{reply, From, timeout}]};

        PrevNbRxFrames -> % nothing new, wait 100ms and check again
            timer:sleep(100), 
            get_new_frame(From, State, PrevNbRxFrames, StartTime);

        _ -> % new frame received
            Fragments = get_stored_payloads(NbRxFrames),
            Reassembled = lowpan:reassemble_datagrams(Fragments),
            case Reassembled of 
                notYetReassembled-> 
                    timer:sleep(100), 
                    get_new_frame(From, State, NbRxFrames, StartTime);
                _-> io:format("Reassembly done~n"),

                    EUI = erpc:call(node(), ieee802154, get_mac_extended_address, []),
                    %lowpan:decompress_ipv6_header(Reassembled, EUI),
                    {next_state, idle_state, State, [{reply, From, Reassembled}]}
            end
    end.

get_stored_payloads(NbRxFrames) ->
    %io:format("Total frame received: ~p~n", [NbRxFrames]),
    
    Payloads = ets:lookup(callback_table, rx_frames),
    
    PayloadsList = [Payload || {rx_frames, Payload} <- Payloads],
    L = lists:flatten(PayloadsList),
    L.


callback_mode() ->
    [state_functions].

terminate(_, _, _) ->
    ok.

code_change(_, _, _, _) ->
    error(not_implemented).

% TODO Timeout state, forwarding, ack


input_callback(Frame, _, _, _) ->
    {_, _, Payload} = Frame, 
    ets:update_counter(callback_table, nb_rx_frames, 1),
    case ets:lookup(callback_table, rx_frames) of
        [] -> ets:insert(callback_table, {rx_frames, [Payload]});
        [{_, Frames}] -> 
            % Ajoutez le nouveau payload à la fin de la liste
            UpdatedFrames = Frames ++ [Payload],
            ets:insert(callback_table, {rx_frames, UpdatedFrames})
    end.


init_ets_callback_table(Node) ->
    erpc:call(Node, ets, insert, [callback_table, {nb_rx_frames, 0}]),
    erpc:call(Node, ets, insert, [callback_table, {rx_frames, []}]).
