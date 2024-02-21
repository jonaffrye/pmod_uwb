-module(lowpan_sender_receiver_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("../src/mac_frame.hrl").
-include("../src/lowpan.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2, init_per_testcase/2, end_per_testcase/2]).
-export([sender/1]).
-export([receiver/1]).
-export([receiver2/1]).

all() -> [{group, simple_tx_rx}].

groups() -> [{simple_tx_rx, [parallel], [sender, receiver, receiver2]}
            ].


%------Default Initialization-----------------------------------------

init_per_group(_, Config) ->
    {NetPid, Network} = lowpan_node:boot_network_node(),

    Node1MacAddress = <<16#CAFEDECA00000001:64>>, 
    Node2MacAddress = <<16#CAFEDECA00000002:64>>,
    Node3MacAddress = <<16#CAFEDECA00000003:64>>,

    % use default address (LL) for both the sender and the receiver 
    Node1Address = lowpan:get_default_LL_add(Node1MacAddress),
    Node2Address = lowpan:get_default_LL_add(Node2MacAddress),
    Node3Address = lowpan:get_default_LL_add(Node3MacAddress),

    io:format("----------------------------------------------------------------"),
    io:format("                          Initialization"),
    io:format("----------------------------------------------------------------~n"),
    io:format("Node1 LL add: ~p~n", [Node1Address]), 
    io:format("Node2 LL add: ~p~n", [Node2Address]),
    io:format("Node3 LL add: ~p~n", [Node3Address]), 
    io:format("----------------------------------------------------------------~n"),

    

    Payload = <<"Hello world! This is an Ipv6 pckt">>,
    PayloadLength = byte_size(Payload),
    

    Ipv6Pckt = <<6:4, 224:8, 2:20, PayloadLength:16, 58:8, 255:8, Node1Address/binary, Node2Address/binary, Payload/binary>>,
    Ipv6Pckt2 = <<6:4, 224:8, 1048575:20, PayloadLength:16, 58:8, 255:8, Node1Address/binary, Node3Address/binary, Payload/binary>>,

    [{net_pid, NetPid}, {network, Network}, {ipv6_packet, Ipv6Pckt}, {ipv6_packet2, Ipv6Pckt2},{node1_address, Node1Address}, {node2_address, Node2Address}, {node3_address, Node3Address},
     {node1_mac_src_address, Node1MacAddress}, {node2_mac_src_address, Node2MacAddress}, {node3_mac_src_address, Node3MacAddress} | Config].

end_per_group(_, Config) ->
    Network = ?config(network, Config),
    NetPid = ?config(net_pid, Config),
    lowpan_node:stop_network_node(Network, NetPid).

init_per_testcase(sender, Config) ->
    Network = ?config(network, Config),

    Node1MacAddress = ?config(node1_mac_src_address, Config),
    Node2MacAddress = ?config(node2_mac_src_address, Config),

    Node1 = lowpan_node:boot_lowpan_node(node1, Network, Node1MacAddress, Node2MacAddress),
    [{node1, Node1} | Config];

init_per_testcase(receiver, Config) ->
    Network = ?config(network, Config),

    Node1MacAddress = ?config(node1_mac_src_address, Config),
    Node2MacAddress = ?config(node2_mac_src_address, Config),
    %Node3MacAddress = ?config(node3_mac_src_address, Config),
    
    Callback = fun lowpan_stack:input_callback/4,
    Node2 = lowpan_node:boot_lowpan_node(node2, Network, Node2MacAddress, Node1MacAddress, Callback), % create receiver node
    [{node2, Node2} | Config];

init_per_testcase(receiver2, Config) ->
    Network = ?config(network, Config),
    Node1MacAddress = ?config(node1_mac_src_address, Config),
    Node3MacAddress = ?config(node3_mac_src_address, Config),

    Callback = fun lowpan_stack:input_callback/4,
    Node3 = lowpan_node:boot_lowpan_node(node3, Network, Node3MacAddress, Node1MacAddress, Callback), % create receiver node
    [{node3, Node3} | Config];


init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _) ->
    ok.

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%------End Default Initialization-----------------------------------------



%--- Test cases -----------------------------------------------------------------------------

sender(Config) ->
    ct:sleep(100),
    ct:pal("Launching node1..."),
    {Pid1, Node1} = ?config(node1, Config),
    IPv6Packet = ?config(ipv6_packet, Config),
    IPv6Packet2 = ?config(ipv6_packet2, Config),
    
    ok = erpc:call(Node1, lowpan_stack, snd_pckt, [IPv6Packet]), 
    ct:sleep(100),
    ok = erpc:call(Node1, lowpan_stack, snd_pckt, [IPv6Packet2]), 
    
    ct:pal("Node1 done"),
    lowpan_node:stop_lowpan_node(Node1, Pid1).


receiver(Config) ->
    %ct:sleep(100),
    ct:pal("Launching node2..."),
    {Pid2, Node2} = ?config(node2, Config),
    ExpectedIpv6 = ?config(ipv6_packet, Config),
    Node2MacAddress = ?config(node2_mac_src_address, Config),
    {CompressedHeader, _} = lowpan:compress_ipv6_header(ExpectedIpv6),
    {_, _, _, _, _,_, _, _, Payload} = lowpan:get_ipv6_pckt_info(ExpectedIpv6),
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/binary>>,

    ReceivedData = erpc:call(Node2, lowpan_stack, rcv_frame, []),
    io:format("Original comp: ~p~n~nReceived comp: ~p~n", [CompressedIpv6Packet,ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    DecompressedFields = lowpan:decompress_ipv6_header(ReceivedData, Node2MacAddress),
    
    %DecompressedPckt = lowpan:convert(DecompressedFields),
    %io:format("Original: ~p~n~nReceived: ~p~n", [ExpectedIpv6,DecompressedPckt]),

    %ExpectedIpv6 = DecompressedPckt,
    
    ct:pal("Node2 done"), 
  
    lowpan_node:stop_lowpan_node(Node2, Pid2).


receiver2(Config) ->
    %ct:sleep(100),
    ct:pal("Launching node3..."),
    {Pid3, Node3} = ?config(node3, Config),
    ExpectedIpv6 = ?config(ipv6_packet2, Config),
   
    {CompressedHeader, _} = lowpan:compress_ipv6_header(ExpectedIpv6),
    {_, _, _, _, _,_, _, _, Payload} = lowpan:get_ipv6_pckt_info(ExpectedIpv6),
    CompressedIpv6Packet = <<CompressedHeader/binary, Payload/binary>>,

    ReceivedData = erpc:call(Node3, lowpan_stack, rcv_frame, []),

    io:format("Expected: ~p~n~nReceived: ~p~n", [CompressedIpv6Packet,ReceivedData]),
    ReceivedData = CompressedIpv6Packet,

    ct:pal("Node3 done"), 
    lowpan_node:stop_lowpan_node(Node3, Pid3).
