-module(lowpan_test_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("../src/lowpan.hrl").


-export([all/0, init_per_testcase/1, end_per_testcase/1]).
-export([
    pkt_encapsulation_test/1,
    fragmentation_test/1,
    datagram_info_test/1,
    reassemble_fragments_list_test/1,
    reassemble_single_fragments_test/1,
    reassemble_full_ipv6_pckt_test/1,
    compress_header_ex1_test/1,
    compress_header_ex2_test/1
]).

all() -> 
    [
        pkt_encapsulation_test,
        fragmentation_test,
        datagram_info_test,
        reassemble_fragments_list_test,
        reassemble_single_fragments_test,
        reassemble_full_ipv6_pckt_test,
        compress_header_ex1_test,
        compress_header_ex2_test
    ].

init_per_testcase(Config) ->
    % Any setup required before suite runs
    Config.

end_per_testcase(_Config) ->
    % Cleanup after suite runs
    ok.

pkt_encapsulation_test(_Config) ->
    Payload = <<"This is an Ipv6 pckt">>, 
    IPv6Header = #ipv6_header{version =  6, traffic_class = 0, flow_label = 0, payload_length = byte_size(Payload),
        next_header = 17, hop_limit = 64, source_address = 1, destination_address = 2},
    IPv6Packet = ipv6:build_ipv6_packet(IPv6Header, Payload),
    DhTypeBinary = <<?IPV6_DHTYPE:8, 0:16>>,
    ToCheck = <<DhTypeBinary/binary, IPv6Packet/binary>>,
    ToCheck = lowpan:pkt_encapsulation(IPv6Header, Payload),
    ok.

fragmentation_test(_Config) ->
    % fragmentation test based on the computation of the size of all fragment payloads
    Payload = <<"This is an Ipv6 pckt">>, 
    IPv6Header = #ipv6_header{version =  6, traffic_class = 0, flow_label = 0, payload_length = byte_size(Payload),
        next_header = 17, hop_limit = 64, source_address = 1, destination_address = 2},
    IPv6Pckt = ipv6:build_ipv6_packet(IPv6Header, Payload),
    Fragments = lowpan:fragment_ipv6_packet(IPv6Pckt),
    ReassembledSize = lists:foldl( fun({_, Fragment}, Acc)-> byte_size(Fragment) + Acc end,
                                    0,Fragments),
    Psize = byte_size(IPv6Pckt),
    Psize = ReassembledSize,
    ok.

datagram_info_test(_Config)->
    Fragment = <<0:5, 1000:11, 12345:16, 5:8, "payload">>,
    {FragType, DatagramSize, DatagramTag, DatagramOffset, Payload} = lowpan:datagram_info(Fragment),
    0 = FragType,
    1000 = DatagramSize,
    12345 = DatagramTag,
    5 = DatagramOffset,
    <<"payload">> = Payload, 
    ok.

reassemble_fragments_list_test(_Config)->
    Data = <<"Hello World!">>, 
    PayloadLen = bit_size(Data),
    FragHeader1 = #frag_header{
        frag_type = 24, datagram_size = PayloadLen, datagram_tag = 25, datagram_offset = 0
    },
    FragHeader2 = #frag_header{
        frag_type = 28, datagram_size = PayloadLen, datagram_tag = 25, datagram_offset = 1
    },
    Frag1 = lowpan:build_datagram_pckt(FragHeader1,<<"Hello ">>),
    Frag2 = lowpan:build_datagram_pckt(FragHeader2,<<"World!">>),
    Fragments = [Frag1, Frag2],
    Reassembled = lowpan:reassemble_datagrams(Fragments),
    <<"Hello World!">> =  Reassembled, 
    ok.

reassemble_single_fragments_test(_Config)->
    Data = <<"Hello World!">>, 
    PayloadLen = bit_size(Data),
    FragHeader1 = #frag_header{
        frag_type = 24, datagram_size = PayloadLen, datagram_tag = 25, datagram_offset = 0
    },
    FragHeader2 = #frag_header{
        frag_type = 28, datagram_size = PayloadLen, datagram_tag = 25, datagram_offset = 1
    },
    Frag1 = lowpan:build_datagram_pckt(FragHeader1, <<"Hello ">>),
    Frag2 = lowpan:build_datagram_pckt(FragHeader2, <<"World!">>),
    DatagramMap = maps:new(), 
    {notYetReassembled, IntermediateMap} = lowpan:reassemble_datagram(Frag1, DatagramMap),
    {Reassembled, _FinalMap} = lowpan:reassemble_datagram(Frag2, IntermediateMap),

    <<"Hello World!">> = Reassembled, 
    ok. 

reassemble_full_ipv6_pckt_test(_Config)->
    Payload = <<"Hello World! This is a basic Ipv6 packet">>, 
    IPv6Header = #ipv6_header{version =  6, traffic_class = 0, flow_label = 0, payload_length = byte_size(Payload),
        next_header = 17, hop_limit = 64, source_address = 1, destination_address = 2},
    Ipv6Pckt = ipv6:build_ipv6_packet(IPv6Header,Payload), 

    FragmentList = lowpan:fragment_ipv6_packet(Ipv6Pckt),
    Fragments = lists:map(fun({FragHeader, FragPayload})->
                                <<FragHeader/binary,FragPayload/binary>> 
                          end, FragmentList),
    Reassembled = lowpan:reassemble_datagrams(Fragments),
    Ipv6Pckt = Reassembled, 
    ok. 

compress_header_ex1_test(_Config)->
    Payload = <<"Hello world this is an ipv6 packet">>,
    PayloadLength = byte_size(Payload),
    Tf = 2#10, Nh = 0, Hlim = 2#11, Cid = 0, Sac = 0, Sam = 2#11, M = 1, Dac = 0, Dam = 2#11,
    ExpectedCarriedInline = #{"DAM" => 1,"NextHeader" => 58,"TrafficClass" => 224},
    InlineData = lowpan:map_to_binary(ExpectedCarriedInline),
    ExpectedHeader = <<Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    
    SrcAddress = <<16#FE80:16, 0:48,16#020164FFFE2FFC0A:64>>,
    DstAddress = <<16#FF02:16,16#00000000000:48, 16#0000000000000001:64>>, 
    Ipv6Pckt = <<6:4, 224:8, 0:20, PayloadLength:16, 58:8, 255:8, SrcAddress/binary, DstAddress/binary, Payload/binary>>,
    
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt),
    
    ExpectedHeader = CompressedHeader, 
            
    CarriedInlineDataOut = {maps:get("DAM",CarriedInlineData),
                            maps:get("NextHeader",CarriedInlineData),
                            maps:get("TrafficClass",CarriedInlineData)
                            },
    %io:format("ExpectedCarriedInline ~p~nCarriedInlineDataOut ~p~n",[ExpectedCarriedInline, CarriedInlineDataOut]), 
    ExpectedCarriedInline = CarriedInlineData,
    ok.

compress_header_ex2_test(_Config)->
    Payload = <<"Hello world this is an ipv6 packet">>,
    PayloadLength = byte_size(Payload), 
    Tf = 2#11, Nh = 0, Hlim = 2#10, Cid = 0, Sac = 1, Sam = 2#01, M = 0, Dac = 1, Dam = 2#00,
    ExpectedCarriedInline = #{"SAM"=>16#0223DFFFFEA9F7AC,"NextHeader" => 6},
    InlineData = lowpan:map_to_binary(ExpectedCarriedInline),
    ExpectedHeader = <<Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam, InlineData/binary>>,
    
    SrcAddress = <<16#2001066073013728:64, 16#0223DFFFFEA9F7AC:64>>,
    DstAddress = <<16#2A00145040070803:64, 16#0000000000001004:64>>, 
    Ipv6Pckt = <<6:4, 0:8, 0:20, PayloadLength:16, 6:8, 64:8, SrcAddress/binary, DstAddress/binary, Payload/binary>>,
    
    {CompressedHeader,CarriedInlineData} = lowpan:compress_ipv6_header(Ipv6Pckt), 
    io:format("Expected ~p~nActual ~p~n",[ExpectedHeader,CompressedHeader]),
    %ExpectedHeader = CompressedHeader, 
    
            
    %CarriedInlineDataOut = {maps:get("NextHeader",CarriedInlineData)},
    ExpectedCarriedInline = CarriedInlineData, 
    ok.
