% @doc robot public API.
-module(robot).

-behavior(application).

-include("mac_layer.hrl").

-export([ds_initiator/0, ds_responder/0]).
%
% Callbacks
-export([start/2]).
-export([stop/1]).

%-define(TU, 1.565444993393822e-11). % 1 t.u. is ~1.5654e-11 s
-define(TU, 15.65e-12).
-define(C, 299792458). % Speed of light
% https://forum.qorvo.com/t/sample-programs/788/3
-define(UUS_TO_DWT_TIME, 65536). % in one UWB µs, there are 65536 t.u (UWB µs are special µs ???)

-define(NBR_MEASUREMENTS, 250).
-define(TX_ANTD, 16450).
-define(RX_ANTD, 16450).

%--- Double-sided two-way ranging -------------------------------------------------------------------
ds_initiator() ->
    % Set the antenna delay -> !! the values should be calibrated
    pmod_uwb:write(tx_antd, #{tx_antd => ?TX_ANTD}),
    pmod_uwb:write(lde_if, #{lde_rxantd => ?RX_ANTD}),
    pmod_uwb:set_frame_timeout(16#FFFF),
    % ? Set preamble timeout too ?
    ds_initiator_loop(?NBR_MEASUREMENTS, {0,0,[],0}).

ds_initiator_loop(0, {Succeeded, Errors, _Measures, Total}) ->
    SuccessRate = Succeeded / Total,
    ErrorRate = Errors / Total,
    io:format("-------------------------------- Summary --------------------------------~n"),
    io:format("Sent ~w request - ratio: ~w/~w - Success rate: ~w - Error rate: ~w~n",[Total, Succeeded, Total, SuccessRate, ErrorRate]),
    io:format("-------------------------------------------------------------------------~n");
ds_initiator_loop(Left, {Succeeded, Errors, Measures, Total}) ->
    case ds_initiator_protocol() of
        ok -> ds_initiator_loop(Left - 1, {Succeeded+1, Errors, Measures, Total+1});
        error -> ds_initiator_loop(Left-1, {Succeeded, Errors+1, Measures, Total+1}) % No response to Poll message -> try again
    end.

ds_initiator_protocol() ->
    % Sending the poll message
    FrameControl = #frame_control{pan_id_compr = ?ENABLED},
    MacHeader = #mac_header{seqnum = 0, dest_pan = <<16#FFFF:16>>, dest_addr = <<16#FFFF:16>>, src_addr = <<16#FFFF:16>>},
    % enabling wait4resp to avoid an early timeout. Here we know that resp will take at least 10000 µs
    mac_layer:mac_send_data(FrameControl, MacHeader, <<"DS_INIT">>, #tx_opts{wait4resp = ?ENABLED, w4r_tim = 20000}),
    io:format("Poll message is sent~n"),

    % Receiving the resp message
    case  mac_layer:mac_receive(true) of
        {_, _, <<"Resp_TX">>} -> #{tx_stamp := PollTXTimestamp} = pmod_uwb:read(tx_time),
                         #{rx_stamp := RespRXTimestamp} = pmod_uwb:read(rx_time), % Getting the reception timestamp of the resp message

                         % Setting up the final message
                         FinalTXTime = RespRXTimestamp + (30000 * ?UUS_TO_DWT_TIME),
                         pmod_uwb:write(dx_time, #{dx_time => FinalTXTime}),
                         FinalTXTimestamp = FinalTXTime + ?TX_ANTD,
                         Message = <<PollTXTimestamp:40, RespRXTimestamp:40, FinalTXTimestamp:40>>,
                         pmod_uwb:write(sys_status, #{txfcg => 2#1}),
                         % Sending the final message
                         mac_layer:mac_send_data(FrameControl, MacHeader, Message, #tx_opts{txdlys = ?ENABLED, tx_delay = FinalTXTime}),
                         io:format("Final message sent~n"),
                         io:format("PollTX: ~w - RespRX ~w - FinalTX ~w~n", [PollTXTimestamp, RespRXTimestamp, FinalTXTimestamp]),
                         io:format("Data sent~n"),
                         timer:sleep(100);
        Err -> io:format("Reception error: ~w~n", [Err]),
               error
    end.


ds_responder() ->
    % Set the antenna delay -> !! the values should be calibrated
    pmod_uwb:write(tx_antd, #{tx_antd => ?TX_ANTD}),
    pmod_uwb:write(lde_if, #{lde_rxantd => ?RX_ANTD}),
    % ? Set preamble timeout too ?
    % Disabling wait t.o. for Poll frame
    Measures = ds_responder_loop(?NBR_MEASUREMENTS, {0, 0, [], 0}),
    io:format("~w~n", [Measures]).

ds_responder_loop(0, {Succeeded, Errors, Measures, Total}) ->
    SuccessRate = Succeeded/Total,
    ErrorRate = Errors/Total,
    MeasureAVG = lists:sum(Measures)/Succeeded,
    StdDev = std_dev(Measures, MeasureAVG, Succeeded, 0),
    io:format("-------------------------------- Summary --------------------------------~n"),
    io:format("Received ~w request - ratio: ~w/~w - Success rate: ~w - Error rate: ~w~n",[Total, Succeeded, Total, SuccessRate, ErrorRate]),
    io:format("Average distance measured: ~w - standard deviation: ~w ~n", [MeasureAVG, StdDev]),
    io:format("Min: ~w - Max ~w~n", [lists:min(Measures), lists:max(Measures)]),
    io:format("-------------------------------------------------------------------------~n"),
    Measures;
ds_responder_loop(N, {Succeeded, Errors, Measures, Total}) ->
    pmod_uwb:write(sys_cfg, #{rxwtoe  => 2#0}),
    case ds_responder_protocol() of
        error_rx_poll -> ds_responder_loop(N-1, {Succeeded, Errors+1, Measures, Total+1});
        error -> ds_responder_loop(N-1, {Succeeded, Errors+1, Measures, Total+1});
        Distance -> ds_responder_loop(N-1, {Succeeded+1, Errors, [Distance | Measures], Total+1})
    end.

ds_responder_protocol() ->
    % Receiving poll message
    case mac_layer:mac_receive() of
        {FrameControl, MacHeader, <<"DS_INIT">>} -> 
            io:format("Poll message received~n"),
            pmod_uwb:set_frame_timeout(16#FFFF), 
            #{rx_stamp := PollRXTimestamp} = pmod_uwb:read(rx_time), % Getting the the reception timestamp of the poll message

            % Setting up and sending the resp message
            RespTXTime = PollRXTimestamp + (30000 * ?UUS_TO_DWT_TIME),
            pmod_uwb:write(dx_time, #{dx_time => RespTXTime}),
            RespMacHeader = #mac_header{src_addr = <<16#FFFF:16>>, dest_pan = MacHeader#mac_header.src_pan, dest_addr = MacHeader#mac_header.src_addr, seqnum = MacHeader#mac_header.seqnum},
            mac_layer:mac_send_data(FrameControl, RespMacHeader, <<"Resp_TX">>, #tx_opts{wait4resp = ?ENABLED, w4r_tim = 20000}),
            io:format("Response message sent~n"),

            % Receiving the final message
            case mac_layer:mac_receive(true)of
                {_, _, <<PollTXTimestamp:40, RespRXTimestamp:40, FinalTXTimestamp:40>>} ->
                    #{tx_stamp := RespTXTimestamp} = pmod_uwb:read(tx_time), % Getting the tx timestamp of the resp message
                    #{rx_stamp := FinalRXTimestamp} = pmod_uwb:read(rx_time), % Getting the rx timestamp of the final message

                    TRound1 = RespRXTimestamp - PollTXTimestamp,
                    TRound2 = FinalRXTimestamp - RespTXTimestamp,
                    TReply1 = RespTXTimestamp - PollRXTimestamp,
                    TReply2 = FinalTXTimestamp - RespRXTimestamp,

                    TProp = (TRound1 * TRound2 - TReply1 * TReply2)/(TRound1 + TRound2 + TReply1 + TReply2),
                    io:format("TProp: ~w~n", [TProp]),
                    TOF = TProp * ?TU,
                    Distance = TOF * ?C,

                    io:format("PollRX: ~w - RespTX ~w - FinalRX ~w~n", [PollRXTimestamp, RespTXTimestamp, FinalRXTimestamp]),
                    io:format("TRound1: ~w - TRound2 ~w - TReply1 ~w - TReply2 ~w ~n", [TRound1, TRound2, TReply1, TReply2]),
                    io:format("Computed distance: ~w~n", [Distance]),
                    if 
                        (PollTXTimestamp =< RespRXTimestamp) and (RespRXTimestamp =< FinalTXTimestamp) and (PollRXTimestamp =< RespTXTimestamp) and (RespTXTimestamp =< FinalRXTimestamp) -> Distance;
                        true -> io:format("Small error~n"), error % There was a wrap around in the clock of one of the GRIP - Throw away the result
                    end;
                Err -> io:format("Reception error: ~w~n", [Err]),
                       error
            end;
        Err -> io:format("Receiving error: ~w~n", [Err]), 
               error_rx_poll
    end.

%--- Tool functions for stats -------------------------------------------------------------------

-spec std_dev(Measures :: list(), Mean :: number(), N :: number(), Acc :: number()) -> number().
std_dev([], _, N, Acc) ->
    math:sqrt(Acc/N);
std_dev([H | T], Mean, N, Acc) ->
    std_dev(T, Mean, N, Acc + math:pow(H-Mean, 2)).

%--- Callbacks -----------------------------------------------------------------

% @private
start(_Type, _Args) -> 
    {ok, Supervisor} = robot_sup:start_link(),
    grisp:add_device(spi2, pmod_uwb),
    % Res = pmod_uwb:read(dev_id),
    {ok, Supervisor}.

% @private
stop(_State) -> ok.
