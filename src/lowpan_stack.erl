-module(lowpan_stack). 
-behaviour(gen_statem).

%-include("lowpan_stack.hrl").
%-include("ieee802154.hrl").
-include("../src/mac_frame.hrl").
-include("lowpan.hrl").

% API
-export([start_link/1, start/1, stop_link/0, stop/0]).

% gen_statem callbacks
-export([init/1, callback_mode/0,terminate/3,code_change/4]).
-export([idle_state/3]).
-export([snd_pckt/1]).
-export([rcv_frame/0]).
-export([input_callback/4]).

-export([pckt_tx_state/3, frame_rx_state/3]).

%%---Helper -----------------------------------------------------------------------------

setup_ets() ->
    ets:new(nodeData, [named_table, public, {keypos, 1}]).

% Set a value in the ETS table
set_nodeData_value(Key, Value) ->
    ets:insert(nodeData, {Key, Value}).

% Get a value from the ETS table
get_nodeData_value(Key) ->
    case ets:lookup(nodeData, Key) of
        [] -> undefined;
        [{_, Value}] -> Value
    end.


%--- API --------------------------------------------------------------------------------

%% @doc Starts the 6lowpan statck and creates a link
%% @end


init(Params) ->
    %init_ets_callback_table(node()), % initialize callback table on mock_phy_net

    SrcMacAdd = maps:get(src_mac_addr, Params), 
    io:format("SrcMacAdd: ~p~n",[SrcMacAdd]),

    setup_ets(),
    set_nodeData_value(srcMacAdd, SrcMacAdd), 

    Data = #{src_mac_addr => SrcMacAdd,  %, dest_mac_addr => DstMacAdd,
            datagram_map => #{}},

    {ok, idle_state, Data}. % idle is the initital state of our system 
    % Data represent all of the data we want to associate with the state machine


-spec start_link(Params::#{}) -> {ok, pid()} | {error, any()}.
start_link(Params) -> 
    gen_statem:start_link({local, ?MODULE}, ?MODULE, Params, []).

% Starts statem
start(Params) -> 
    gen_statem:start({local, ?MODULE}, ?MODULE, Params, []),
    
    io:format("lowpan stack launched on node ~p~n",[node()]).
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
    gen_statem:cast(?MODULE, {frame_rx, self()}), % get Pid and ref

receive
    {reassembled_packet, ReassembledPacket} -> 
        ReassembledPacket
    %after 10000 -> error
end.


input_callback(Frame, _, _, _) ->
    {_, _, Payload} = Frame, 
    io:format("New frame received~n~p~n",[Payload]),
    {FC, MH, Payload} = Frame,

    SrcMacAdd = get_nodeData_value(srcMacAdd),
    DstMacAdd = MH#mac_header.dest_addr, 
    %io:format("~nIn Callback~nSrcMacAdd: ~p~nDstMacAdd: ~p~n",[SrcMacAdd,DstMacAdd]),

    From = MH#mac_header.src_addr, 

    io:format("From node~p~n",[From]),    
    BroadcastAdd = <<"ÿÿ">>,
    case DstMacAdd of
        SrcMacAdd ->
            io:format("Dest reached, Forwarding to lowpan layer~n"),
            gen_statem:cast(?MODULE, {new_frame, Payload});
        
        BroadcastAdd->
            io:format("Ack received~n");

        _ ->
            NewMH = MH#mac_header{src_addr = SrcMacAdd, dest_addr = DstMacAdd},
            NewFrame = {FC, NewMH, Payload},
            io:format("Not the dest, Keep forwarding~n"),
            ieee802154:transmission(NewFrame)
        
    end.
    


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

idle_state({call, _}, _, Data) ->
    {next_state, pckt_tx_state, Data, [{next_event, internal,ok}]};

% Idle call for frame reception
idle_state(cast, {frame_rx, From}, Data) ->
    {next_state, frame_rx_state, Data, [{next_event, internal, {frame_rx, idle_state,From}}]}; 

idle_state(cast, {new_frame, Payload}, Data = #{datagram_map := DatagramMap}) ->
    UpdatedMap = put_and_reassemble(Payload, DatagramMap, Data),
    {keep_state, Data#{datagram_map => UpdatedMap}};

idle_state(cast, {collected, Tag, UpdatedMap},  StateData = #{caller := From}) ->
    ReassembledPacket = lowpan:reassemble(Tag, UpdatedMap),
    io:format("Complete for pckt ~p~n", [Tag]),
    From ! {reassembled_packet, ReassembledPacket}, 
    {next_state, idle_state, StateData}.


% --- Internal state -----------
% Handling packet transmission state
pckt_tx_state(_EventType, {pckt_tx, IdleState, Ipv6Pckt, From}, Data = #{src_mac_addr := SrcMacAddress}) ->
    PcktInfo = lowpan:get_ipv6_pckt_info(Ipv6Pckt),
    DestAddress = PcktInfo#ipv6PckInfo.destAddress, 
    Payload = PcktInfo#ipv6PckInfo.payload, 
    DestMacAddress = lowpan:encode_integer(DestAddress), % because return DestAddress is in integer form (TODO)

    {CompressedHeader, _} = lowpan:compress_ipv6_header(Ipv6Pckt), % 1st - compress the header
    CompressedPacket = <<CompressedHeader/binary, Payload/binary>>,
    CompPcktLen = byte_size(CompressedPacket),
    io:format("Compressed Pckt length: ~p bytes~n",[CompPcktLen]),
    Fragmentationcheck = lowpan:trigger_fragmentation(CompressedPacket),  % 2nd - check if fragmentation is needed, if so return graments list
    

    case Fragmentationcheck of 
        {true, Fragments} ->
            Response = lists:foreach(fun({Header, FragPayload})-> % FragPayload consist of <<dispatch_head_compr to orig payload>>
                                            Pckt = <<Header/binary,FragPayload/binary>>,
                                            Transmit = ieee802154:transmission(
                                                            {#frame_control{frame_type = ?FTYPE_DATA,src_addr_mode = ?EXTENDED, dest_addr_mode = ?EXTENDED, ack_req = ?ENABLED}, 
                                                            #mac_header{src_addr = SrcMacAddress, dest_addr = DestMacAddress},Pckt}),
                                            case Transmit of 
                                                {ok, _} -> ok; 
                                                {error, Error} -> io:format("Errro: ~p~n",[Error])
                                            end
                        end, Fragments),
            {next_state, IdleState, Data#{fragments => Fragments}, [{reply, From, Response}]};
        false ->
                Header = #frag_header{
                            frag_type = ?FRAG1_DHTYPE,
                            datagram_size = CompPcktLen,
                            datagram_tag =  rand:uniform(65536),
                            datagram_offset = 0
                        },      
                UnFragPckt = lowpan:build_datagram_pckt(Header, CompressedPacket),                          
                %UnFragPckt = <<Header,CompressedPacket>>,
                %io:format("UnFragPckt: ~p~n",[byte_size(UnFragPckt)]),
                Transmit = ieee802154:transmission({#frame_control{frame_type = ?FTYPE_DATA,src_addr_mode = ?EXTENDED, dest_addr_mode = ?EXTENDED, ack_req = ?ENABLED}, 
                                                     #mac_header{src_addr = SrcMacAddress, dest_addr = DestMacAddress},UnFragPckt}),
                case Transmit of 
                    {ok, _} -> {next_state, IdleState, Data#{fragments => []}, [{reply, From, ok}]} ; 
                    {error, Error} -> {next_state, IdleState, Data#{fragments => []}, [{reply, From, Error}]} 
                end                              
    end.

% State for handling packet receiving
frame_rx_state(_EventType, {frame_rx, _, From}, Data) ->
    Rx_on = ieee802154:rx_on(), % ensures continuous reception 
    case Rx_on of 
        ok ->
            io:format("Rx_on activated on node: ~p~n",[node()]), 
            NewData = Data#{caller => From},
            {next_state, idle_state, NewData};
        {error, E} ->
            {next_state, idle_state, Data, [{reply, From, {error, E}}]}
    end.


put_and_reassemble(Frame, Map, Data)->
    DtgInfo = lowpan:datagram_info(Frame),
    Size = DtgInfo#datagramInfo.datagramSize, 
    Tag = DtgInfo#datagramInfo.datagramTag, 
    Offset = DtgInfo#datagramInfo.datagramOffset, 
    Payload = DtgInfo#datagramInfo.payload, 

    io:format("Received ~pth payload: ~p bytes~n",[Offset+1,byte_size(Payload)]),
    {UpdatedMap, DatagramComplete} = case maps:is_key(Tag, Map) of
        true ->
            {NewMap, UpdatedCmpt} = check_duplicate_frag(Map, Tag, Offset, Size, Payload),
            %{NewMap, UpdatedCmpt} = update_datagram_map(Size, Tag, Offset, Payload, Map),
            {NewMap, UpdatedCmpt};
            
        false ->
            CurrSize = byte_size(Payload),
            Datagram = #datagram{tag = Tag, size = Size, cmpt=CurrSize, fragments = #{Offset=>Payload}},
            NewMap = maps:put(Tag, Datagram, Map),
            AllReceived = CurrSize == Size,
            {NewMap, AllReceived} % return Map and "fullness" of frame
    end,
    io:format("Map: ~p~n",[UpdatedMap]),
    
    case DatagramComplete of
        true ->  gen_statem:cast(?MODULE, {collected, Tag, UpdatedMap});
        false -> io:format("Not all received: ~n"), {keep_state, Data#{datagram_map => UpdatedMap}}
    end,
    UpdatedMap.

check_duplicate_frag(Map, Tag, Offset, Size, Payload)->
    Datagram = maps:get(Tag, Map),
    FragmentsMap = Datagram#datagram.fragments,
    KnownFragment = maps:is_key(Offset, FragmentsMap),
    
    case KnownFragment of 
        true -> io:format("Duplicate frame detected~n"),{Map,false}; 
        false -> io:format("Not a Duplicated frame~n"), update_datagram_map(Size, Tag, Offset, Payload, Map)
    end. 

update_datagram_map(Size, Tag, Offset, Payload, Map)->
    OldDatagram = maps:get(Tag, Map),
    CurrSize = byte_size(Payload),
    UpdatedCmpt = OldDatagram#datagram.cmpt + CurrSize,
    FragmentsMap = OldDatagram#datagram.fragments,
    NewFragments = FragmentsMap#{Offset => Payload},
    UpdatedDatagram = OldDatagram#datagram{cmpt = UpdatedCmpt, fragments = NewFragments},
    NewMap = maps:put(Tag, UpdatedDatagram, Map), 
    AllReceived = UpdatedCmpt == Size, 
    io:format("Pckt Size: ~p bytes ~n", [Size]),
    io:format("Current pckt len: ~p bytes~n",[UpdatedCmpt]),
    {NewMap, AllReceived}.



callback_mode() ->
    [state_functions].

terminate(_, _, _) ->
    ok.

code_change(_, _, _, _) ->
    error(not_implemented).

