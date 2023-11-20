-module(ieee802154_mac_layer_SUITE).

-include_lib("common_test/include/ct.hrl").

-include("../src/mac_frame.hrl").

-export([init_per_group/2, end_per_group/2]).
-export([all/0, groups/0]).

-export([mac_message_from_api/1]).
-export([mac_message_pan_id_not_compressed/1]).
-export([mac_message_broadcast/1]).
-export([decode_mac_message/1]).
-export([decode_mac_message_uncompressed_pan_id/1]).
-export([decode_ack_frame_from_device/1]).
-export([decode_mac_message_no_src/1]).
-export([decode_mac_message_no_src_no_compt/1]).
-export([encode_ack_frame/1]).
-export([encode_decode_extended_address/1]).
-export([encode_decode_no_payload/1]).
-export([encode_decode_src_pan_coord/1]).
-export([encode_decode_src_pan_coord_pan_id_compr/1]).
-export([encode_decode_dest_pan_coord/1]).
-export([encode_decode_dest_pan_coord_pan_id_compr/1]).

-export([mac_get_set_ext_mac_addr/1]).
-export([mac_get_set_short_mac_addr/1]).
-export([mac_get_set_pan_id/1]).
-export([mac_get_set_unknown_value/1]).

-export([mac_tx_invalid_address/1]).

all() -> [{group, encode_decode},
          {group, mac_get_set},
          {group, tx}].

groups() -> [{encode_decode, [parallel], [mac_message_from_api,
                                          mac_message_pan_id_not_compressed,
                                          mac_message_broadcast,
                                          decode_mac_message_uncompressed_pan_id,
                                          decode_ack_frame_from_device,
                                          decode_mac_message_no_src,
                                          decode_mac_message_no_src_no_compt,
                                          encode_ack_frame,
                                          encode_decode_extended_address,
                                          encode_decode_no_payload,
                                          encode_decode_src_pan_coord,
                                          encode_decode_src_pan_coord_pan_id_compr,
                                          encode_decode_dest_pan_coord,
                                          encode_decode_dest_pan_coord_pan_id_compr]},
             {mac_get_set, [parallel], [mac_get_set_ext_mac_addr,
                                        mac_get_set_short_mac_addr,
                                        mac_get_set_pan_id,
                                        mac_get_set_unknown_value]},
             {tx, [parallel], [mac_tx_invalid_address]}].

init_per_group(tx, Config) -> init_per_group(mac_get_set, Config);
init_per_group(mac_get_set, Config) ->
    mock_phy:start(spi2, #{}),
    MacState = gen_mac_layer:start(mac_layer, #{phy_layer => mock_phy, duty_cycle => duty_cycle_non_beacon}),
    [{mac_state, MacState} | Config];
init_per_group(_, Config) ->
    Config.

end_per_group(_, _) -> ok.

%--- Test cases: encode_decode group --------------------------------------------------

mac_message_from_api(_Config) ->
    FrameControl = #frame_control{ack_req = ?ENABLED, pan_id_compr = ?ENABLED, frame_version = 2#00},
    MacHeader = #mac_header{seqnum = 0, dest_pan = <<16#DECA:16>>, dest_addr = <<"RX">>, src_addr = <<"TX">>},
    <<16#6188:16, 0:8, 16#CADE:16, "XR", "XT", "Hello">> = mac_frame:encode(FrameControl, MacHeader, <<"Hello">>).

mac_message_pan_id_not_compressed(_Config) ->
    FrameControl = #frame_control{ack_req = ?ENABLED, pan_id_compr = ?DISABLED, frame_version = 2#00},
    MacHeader = #mac_header{seqnum = 0, dest_pan = <<16#DECA:16>>, dest_addr = <<"RX">>, src_pan = <<16#DECA:16>>, src_addr = <<"TX">>},
    <<16#2188:16, 0:8, 16#CADE:16, "XR", 16#CADE:16, "XT", "Hello">> = mac_frame:encode(FrameControl, MacHeader, <<"Hello">>).

mac_message_broadcast(_Config) ->
    FrameControl = #frame_control{ack_req = ?ENABLED, pan_id_compr = ?DISABLED, frame_version = 2#00},
    MacHeader = #mac_header{seqnum = 0, dest_pan = <<16#FFFF:16>>, dest_addr = <<16#FFFF:16>>, src_pan = <<16#FFFF:16>>, src_addr = <<16#FFFF:16>>},
    <<16#2188:16, 0:8, 16#FFFF:16, 16#FFFF:16, 16#FFFF:16, 16#FFFF:16, "Hello">> = mac_frame:encode(FrameControl, MacHeader, <<"Hello">>).

decode_mac_message(_Config) ->
    Message = <<16#6188:16, 0:8, 16#CADE:16, "XR", "XT", "Hello">>,
    FrameControl = #frame_control{ack_req = ?ENABLED, pan_id_compr = ?ENABLED, frame_version = 2#00},
    MacHeader = #mac_header{seqnum = 0, dest_pan = <<16#DECA:16>>, dest_addr = <<"RX">>, src_pan = <<16#DECA:16>>, src_addr = <<"TX">>},
    {FrameControl, MacHeader, <<"Hello">>} = mac_frame:decode(Message).

decode_mac_message_uncompressed_pan_id(_Config) ->
    Message = <<16#2188:16, 0:8, 16#CADE:16, "XR", 16#CADE:16, "XT", "Hello">>,
    FrameControl = #frame_control{ack_req = ?ENABLED, frame_version = 2#00},
    MacHeader = #mac_header{seqnum = 0, dest_pan = <<16#DECA:16>>, dest_addr = <<"RX">>, src_pan = <<16#DECA:16>>, src_addr = <<"TX">>},
    {FrameControl, MacHeader, <<"Hello">>} = mac_frame:decode(Message).

decode_ack_frame_from_device(_Config) ->
    Message = <<16#0200:16, 50:8>>,
    FrameControl = #frame_control{frame_type = ?FTYPE_ACK, src_addr_mode = ?NONE, dest_addr_mode = ?NONE},
    MacHeader = #mac_header{seqnum = 50},
    {FrameControl, MacHeader, <<>>} = mac_frame:decode(Message).

% If Src address mode is zero and frame isn't an ACK. It implies that the frame comes from the PAN coordinator
decode_mac_message_no_src(_Config) -> 
    Message = <<16#4108:16, 22:8, 16#CADE:16, 16#CDAB:16, "Test">>,
    FrameControl = #frame_control{frame_type = ?FTYPE_DATA, pan_id_compr = ?ENABLED, dest_addr_mode = ?SHORT_ADDR, src_addr_mode = ?NONE},
    % SRC addr set to zero because can't imply the addr of the PAN coordinator at this level
    MacHeader = #mac_header{seqnum = 22, dest_pan = <<16#DECA:16>>, dest_addr = <<16#ABCD:16>>, src_pan = <<>>, src_addr = <<>>},
    {FrameControl, MacHeader, <<"Test">>} = mac_frame:decode(Message).

decode_mac_message_no_src_no_compt(_Config) -> 
    Message = <<16#0108:16, 22:8, 16#CADE:16, 16#CDAB:16, "Test">>,
    FrameControl = #frame_control{frame_type = ?FTYPE_DATA, pan_id_compr = ?DISABLED, dest_addr_mode = ?SHORT_ADDR, src_addr_mode = ?NONE},
    % SRC addr set to zero because can't imply the addr of the PAN coordinator at this level
    MacHeader = #mac_header{seqnum = 22, dest_pan = <<16#DECA:16>>, dest_addr = <<16#ABCD:16>>, src_pan = <<>>, src_addr = <<>>},
    {FrameControl, MacHeader, <<"Test">>} = mac_frame:decode(Message).

encode_ack_frame(_Config) ->
    FramePendingDisabled = mac_frame:encode_ack(?DISABLED, 42),
    <<16#0200:16, 42:8>> = FramePendingDisabled,

    FramePendingEnabled = mac_frame:encode_ack(?ENABLED, 200),
    <<16#1200:16, 200:8>> = FramePendingEnabled.

encode_decode_extended_address(_Config) ->
    FrameControl = #frame_control{src_addr_mode = ?EXTENDED, dest_addr_mode = ?EXTENDED},
    MacHeader = #mac_header{src_addr = <<16#DECACAFE0001:64>>, dest_addr = <<16#DECACAFE0002:64>>},
    Payload = <<"Test">>,
    {FrameControl, MacHeader, Payload} = mac_frame:decode(mac_frame:encode(FrameControl, MacHeader, Payload)).

encode_decode_no_payload(_Config) ->
    FrameControl = #frame_control{src_addr_mode = ?EXTENDED, dest_addr_mode = ?EXTENDED},
    MacHeader = #mac_header{src_addr = <<16#DECACAFE0001:64>>, dest_addr = <<16#DECACAFE0002:64>>},
    Encoded = mac_frame:encode(FrameControl, MacHeader), % TODO chce the encoded value
    {FrameControl, MacHeader, <<>>} = mac_frame:decode(Encoded).

encode_decode_src_pan_coord(_Config) ->
    FrameControl = #frame_control{src_addr_mode = ?NONE,  dest_addr_mode = ?SHORT_ADDR},
    MacHeader = #mac_header{dest_addr = <<16#CAFE:16>>, src_addr = <<>>, src_pan = <<>>},
    Payload = <<"This is a frame originating from the PAN coordinator">>,
    Encoded = mac_frame:encode(FrameControl, MacHeader, Payload),
    <<16#0108:16, 0:8, 16#FFFF:16, 16#FECA:16, Payload/bitstring>> = Encoded,
    {FrameControl, MacHeader, Payload} = mac_frame:decode(Encoded).

encode_decode_src_pan_coord_pan_id_compr(_Config) ->
    FrameControl = #frame_control{src_addr_mode = ?NONE,  dest_addr_mode = ?SHORT_ADDR, pan_id_compr = ?ENABLED},
    MacHeader = #mac_header{dest_addr = <<16#CAFE:16>>, src_addr = <<>>, src_pan = <<>>},
    Payload = <<"This is a frame originating from the PAN coordinator">>,
    Encoded = mac_frame:encode(FrameControl, MacHeader, Payload),
    <<16#4108:16, 0:8, 16#FFFF:16, 16#FECA:16, Payload/bitstring>> = Encoded,
    {FrameControl, MacHeader, Payload} = mac_frame:decode(Encoded).

encode_decode_dest_pan_coord(_Config) ->
    FrameControl = #frame_control{dest_addr_mode = ?NONE, src_addr_mode = ?SHORT_ADDR},
    MacHeader = #mac_header{src_addr = <<16#DECA:16>>, dest_addr = <<>>, dest_pan = <<>>}, % Not mandatory to set dest address to <<>> but needed here for the encode/decode check
    Payload = <<"This is a frame for the PAN coordinator">>,
    Encoded = mac_frame:encode(FrameControl, MacHeader, Payload),
    <<16#0180:16, 0:8, 16#FFFF:16, 16#CADE:16, Payload/bitstring>> = Encoded,
    {FrameControl, MacHeader, Payload} = mac_frame:decode(Encoded).

encode_decode_dest_pan_coord_pan_id_compr(_Config) ->
    FrameControl = #frame_control{dest_addr_mode = ?NONE, src_addr_mode = ?SHORT_ADDR, pan_id_compr = ?ENABLED},
    MacHeader = #mac_header{src_addr = <<16#DECA:16>>, dest_addr = <<>>, dest_pan = <<>>}, % Not mandatory to set dest address to <<>> but needed here for the encode/decode check
    Payload = <<"This is a frame for the PAN coordinator">>,
    Encoded = mac_frame:encode(FrameControl, MacHeader, Payload),
    <<16#4180:16, 0:8, 16#FFFF:16, 16#CADE:16, Payload/bitstring>> = Encoded,
    {FrameControl, MacHeader, Payload} = mac_frame:decode(Encoded).

%--- Test cases: mac_get_set --------------------------------------------------
mac_get_set_ext_mac_addr(Config) ->
    MacState = ?config(mac_state, Config),
    EncodedAddress = <<16#DECACAFE00000001:64>>,
    {ok, State2, <<_/bitstring>>} = gen_mac_layer:get(MacState, mac_extended_address),
    {ok, State3} = gen_mac_layer:set(State2, mac_extended_address, EncodedAddress),
    {ok, _, EncodedAddress} = gen_mac_layer:get(State3, mac_extended_address).
 
mac_get_set_short_mac_addr(Config) -> 
    MacState = ?config(mac_state, Config),
    EncodedAddress = <<16#1337:16>>,
    {ok, State2, <<_/bitstring>>} = gen_mac_layer:get(MacState, mac_short_address),
    {ok, State3} = gen_mac_layer:set(State2, mac_short_address, EncodedAddress),
    {ok, _, EncodedAddress} = gen_mac_layer:get(State3, mac_short_address).

mac_get_set_pan_id(Config) -> 
    MacState = ?config(mac_state, Config),
    PanID = <<16#00BE:16>>,
    {ok, State2, <<_/bitstring>>} = gen_mac_layer:get(MacState, mac_pan_id),
    {ok, State3} = gen_mac_layer:set(State2, mac_pan_id, PanID),
    {ok, _, PanID} = gen_mac_layer:get(State3, mac_pan_id).

mac_get_set_unknown_value(Config) ->
    MacState = ?config(mac_state, Config),
    {error, State, unsupported_attribute} = gen_mac_layer:get(MacState, fake_attribute),
    {error, _, unsupported_attribute} = gen_mac_layer:set(State, fake_attribute, fake_value).

%--- Test cases: tx ----------------------------------------------------------
mac_tx_invalid_address(Config) ->
    MacState = ?config(mac_state, Config),
    {error, _State, invalid_address} = gen_mac_layer:tx(MacState, #frame_control{src_addr_mode = ?NONE, dest_addr_mode = ?NONE}, #mac_header{}, <<"Invalid address">>).