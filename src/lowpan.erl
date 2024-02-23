- module(lowpan). 

-include("lowpan.hrl").
%-include("mac_layer.hrl").
%-include("ieee802154.hrl").

-export([pkt_encapsulation/2,create_hc1_dtgm/2,fragment_ipv6_packet/1,reassemble_datagram/2,reassemble_datagrams/1,
        build_hc1_header/1,get_ipv6_pkt/2,datagram_info/1,compress_ipv6_header/1, build_datagram_pckt/2,
        convert_hc1_tuple_to_bin/1, get_ipv6_pckt_info/1, get_ipv6_payload/1, get_ipv6_header/1,
        map_to_binary/1, binary_to_lis/1, decompress_ipv6_header/2, get_default_LL_add/1, get_mac_add/1, tuple_to_bin/1]).



get_ipv6_pkt(Header, Payload)->
    ipv6:build_ipv6_packet(Header, Payload).

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                             FROM IPv6 to Mac layer  
%
%------------------------------------------------------------------------------------------------------------------------------------------------------


%-------------------------------------------------------------------------------
% @doc create an uncompressed 6lowpan packet from an Ipv6 packet
% @equiv pkt_encapsulation()
% @end
%-------------------------------------------------------------------------------
pkt_encapsulation(Header, Payload)->
    Ipv6Pckt = get_ipv6_pkt(Header, Payload), 
    DhTypeBinary = <<?IPV6_DHTYPE:8, 0:16>>, 
    <<DhTypeBinary/binary, Ipv6Pckt/binary>>.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                               Header compression
%
%------------------------------------------------------------------------------------------------------------------------------------------------------


%-------------------------------------------------------------------------------
% @doc Creates a compression header
% @param IphcHeader: Ipv6 header
% @returns a bitstring containing HC1 header fields
% @end
%-------------------------------------------------------------------------------
build_hc1_header(IphcHeader)->
    #iphc_header{
        dispatch = Dispatch, tf = Tf, nh = Nh, hlim = Hlim, cid = Cid,
        sac = Sac, sam = Sam, m = M, dac = Dac, dam = Dam
    } = IphcHeader,

    <<Dispatch:8,Tf:2,Nh:1,Hlim:2,Cid:1,Sac:1,Sam:2,M:1,Dac:1,Dam:2>>.


%-------------------------------------------------------------------------------
% @doc create a compressed 6lowpan packet from an Ipv6 packet
% @equiv create_hc1_dtgm(IphcHeader)
% @end
%-------------------------------------------------------------------------------
create_hc1_dtgm(IphcHeader, Payload)->
    <<IphcHeader/bitstring,Payload/bitstring>>.

get_ipv6_pckt_info(Ipv6Pckt) ->
    <<Version:4, TrafficClass:8, FlowLabel:20, PayloadLength:16, NextHeader:8, HopLimit:8,
      SourceAddress:128, DestAddress:128, Payload/binary>> = Ipv6Pckt,
    {Version, TrafficClass, FlowLabel, PayloadLength, NextHeader, HopLimit, SourceAddress, DestAddress, Payload}.

get_mac_add(Int) ->
   encode_integer(Int).

get_ipv6_header(Ipv6Pckt) ->
    <<Version:4, TrafficClass:8, FlowLabel:20, PayloadLength:16, NextHeader:8, HopLimit:8,
      SourceAddress:128, DestAddress:128, _>> = Ipv6Pckt,

    {Version, TrafficClass, FlowLabel, PayloadLength, NextHeader, HopLimit, SourceAddress, DestAddress}.

get_ipv6_payload(Ipv6Pckt) ->
    <<_:192, _:128, Payload/binary>> = Ipv6Pckt,
    Payload.


%-------------------------------------------------------------------------------
% @doc compress an Ipv6 packet header
% @returns a tuple containing the compressed header, the payload and the values 
% that should be carry inline
% @end
%-------------------------------------------------------------------------------
compress_ipv6_header(Ipv6Pckt)->
    {_, TrafficClass, FlowLabel, _, NextHeader,
     HopLimit, SourceAddress, DestAddress, _} = get_ipv6_pckt_info(Ipv6Pckt),
    
    Map = #{},
    List = [], 

    {TF, UpdateMap1, UpdatedList1} = process_tf(TrafficClass, FlowLabel,Map, List),
    {NH, UpdateMap2, UpdatedList2} = process_nh(NextHeader, UpdateMap1, UpdatedList1),
    {HLIM, UpdateMap3, UpdatedList3} = process_hlim(HopLimit, UpdateMap2, UpdatedList2),
    CID = process_cid(SourceAddress), 
    SAC = process_sac(SourceAddress),
    {SAM, UpdateMap4, UpdatedList4} = process_sam(SAC, SourceAddress, UpdateMap3, UpdatedList3),
    M = process_m(DestAddress),
    DAC = process_dac(DestAddress),
    {DAM, CarrInlineMap, CarrInlineList} = process_dam(M, DAC, DestAddress, UpdateMap4, UpdatedList4),


    io:format("CarrInlineMap: ~p~n", [CarrInlineMap]),
    %io:format("CarrInlineList: ~p~n", [CarrInlineList]),
    CarrInlineBin = list_to_binary(CarrInlineList),%encode_list_to_bin(CarrInlineList),

    io:format("CarrInlineBin ~p~n", [CarrInlineBin]),

    % TODO add HC_DHTYPE
    CompressedHeader = <<TF, NH, HLIM, CID, SAC, SAM, M, DAC, DAM,CarrInlineBin/binary>>, 
    
    {CompressedHeader, CarrInlineMap}.

%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Packet Compression Helper
%------------------------------------------------------------------------------------------------------------------------------------------------------

encode_list_to_bin(List) -> 
    EncodedValues = [encode_integer(I) || I <- List],
    list_to_bin(EncodedValues).
%% Use to optimize encoding 
encode_integer(I) when I =< 255 ->
    <<I:8>>;
encode_integer(I) when I =< 65535 ->
    <<I:16>>;
encode_integer(I) when I =< 4294967295 ->
    <<I:32>>;
encode_integer(I) ->
    <<I:64>>.

list_to_bin(ListOfBinaries) ->
    lists:foldl(fun(Bin, Acc) -> <<Acc/binary, Bin/binary>> end, <<>>, ListOfBinaries).

map_to_binary(CarriedInlineMap) ->
    Values = maps:values(CarriedInlineMap), %get value from map
    BinaryValues = encode_list_to_bin(lists:reverse(Values)), 
    BinaryValues.

map_to_tuple(CarriedInlineMap) ->
    Values = maps:values(CarriedInlineMap), %get value from map
    %io:format("Recovered values: ~p~n", [Values]),
    Tuple = erlang:list_to_tuple(Values), 

    Tuple.

binary_to_tuple(Bin)->
    erlang:list_to_tuple(binary_to_lis(Bin)). 

binary_to_lis(BinaryValues) ->
    Values = erlang:binary_to_list(BinaryValues), % binary to integer list conversion
    %io:format("Recovered values: ~p~n", [Values]),
    Values.


convert_hc1_tuple_to_bin(IphcHeaderTuple)->
    {Tf, Nh, Hlim, Cid, Sac, Sam, M, Dac, Dam} = IphcHeaderTuple,

    % we add 3 padding bits to make it a multiple of 8
    Binary = <<Tf:2, Nh:1, Hlim:2, Cid:1, Sac:1, Sam:2, M:1, Dac:1, Dam:2, 0:3>>,
    Binary.


%-------------------------------------------------------------------------------
% @private
% @doc process the TrafficClass and Flow label fields 
% @returns a tuple containing the compressed values and the CarrInlineMap map
% @end
%-------------------------------------------------------------------------------
process_tf(TrafficClass, FlowLabel, CarrInlineMap, CarrInlineList) ->
    <<DSCP:6, ECN:2>> = <<TrafficClass:8>>, % TrafficClass integer to a bitstring
    case {ECN, DSCP, FlowLabel} of
        {0, 0, 0} -> 
            {2#11, CarrInlineMap, CarrInlineList}; % Traffic Class and Flow Label are elided

        {_, _, 0} -> 
            UpdatedMap = CarrInlineMap#{"TrafficClass"=>TrafficClass},
            Bin = <<TrafficClass:8>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {2#10, UpdatedMap, UpdatedList};% Flow Label is elided
            
        {_, 0, _} -> 
            UpdatedMap = CarrInlineMap#{"ECN"=>ECN,"FlowLabel"=>FlowLabel},
            Bin = <<ECN:8, FlowLabel:24>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {2#01, UpdatedMap, UpdatedList}; % DSCP is elided
        _ -> 
            UpdatedMap = CarrInlineMap#{"TrafficClass"=>TrafficClass,"FlowLabel"=>FlowLabel},
            Bin = <<TrafficClass:8, FlowLabel:24>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {2#00, UpdatedMap,UpdatedList}  % ECN, DSCP, and Flow Label are present

    end.

%-------------------------------------------------------------------------------
% @private
% @doc process the NextHeader field 
% @returns a tuple containing the compressed value and the CarrInlineMap map
% @end
%-------------------------------------------------------------------------------
process_nh(NextHeader, CarrInlineMap,CarrInlineList) when NextHeader == 17 -> 
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = CarrInlineList ++ L,
    {0, CarrInlineMap#{"NextHeader"=>17}, UpdatedList}; % UDP %TODO check compression for UDP
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == 6 -> 
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = CarrInlineList ++ L,
    {0, CarrInlineMap#{"NextHeader"=>6},UpdatedList}; % TCP
process_nh(NextHeader, CarrInlineMap, CarrInlineList) when NextHeader == 58 -> 
    Bin = <<NextHeader>>,
    L = [Bin],
    UpdatedList = CarrInlineList ++ L,
    {0, CarrInlineMap#{"NextHeader"=>58},UpdatedList}; % ICMPv6
process_nh(_, CarrInlineMap, CarrInlineList)  -> {1,CarrInlineMap,CarrInlineList}. % compressed usig LOWPAN_NHC

%-------------------------------------------------------------------------------
% @private
% @doc process the HopLimit field 
% @returns a tuple containing the compressed value and the CarrInlineMap map
% @end
%-------------------------------------------------------------------------------
process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 1  -> 
    %UpdatedList = CarrInlineList++[1],
    {2#01, CarrInlineMap,CarrInlineList }; % UDP

process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 64  -> 
    %UpdatedList = CarrInlineList++[64],
    {2#10, CarrInlineMap, CarrInlineList};

process_hlim(HopLimit, CarrInlineMap, CarrInlineList) when HopLimit == 255 -> 
    %UpdatedList = CarrInlineList ++[255],
    {2#11, CarrInlineMap, CarrInlineList};

process_hlim(HopLimit, CarrInlineMap, CarrInlineList)-> 
    Bin = <<HopLimit:8>>,
    L = [Bin],
    UpdatedList = CarrInlineList++L,
    {2#00, CarrInlineMap#{"HopLimit"=> HopLimit}, UpdatedList}.

%-------------------------------------------------------------------------------
% @private
% @doc process for the Context Identifier Extension field 
% @returns the compressed value 
% @end
%-------------------------------------------------------------------------------
process_cid(SrcAdd) ->
    % determine prefix type
    <<Prefix:16, _/binary>> = <<SrcAdd:128>>,
    case Prefix of
        16#FE80 -> 0; % (link local add) no additional Context Identifier Extension
        16#FF00 -> 0; % multicast 
        16#FF01 -> 0; % multicast 
        16#FD00 -> 0; % mesh local prefix
        16#2001 -> 0; % global prefix 1 (unicast)
        %16#2003 -> 1; % global prefix 2 (unicast)
        _ -> 1        % an additional 8-bit Context Identifier Extension field is used
    end.

%-------------------------------------------------------------------------------
% @private
% @doc process the Source Address Compression 
% @returns the compressed value
% @end
%-------------------------------------------------------------------------------
process_sac(SrcAdd) ->
    <<Prefix:16, _/binary>> = <<SrcAdd:128>>,
    
    case Prefix of
        16#FE80 -> 0; % link-local
        % multicast addresses
        16#FF01 -> 0;
        16#FF02 -> 0;
        16#FF03 -> 0;
        16#FF04 -> 0;
        16#FF05 -> 0; 
        16#FF06 -> 0;
        16#FF07 -> 0;
        16#FF08 -> 0;
        16#FF09 -> 0;
        16#FF0A -> 0;
        16#FF0B -> 0;
        16#FF0C -> 0;
        16#FF0D -> 0;
        16#FF0E -> 0; 
        16#FF0F -> 0;
        16#0000 -> 0; % can be elided
        16#2001 -> 1;  %stateful
        16#FD00 ->1; 
        _ -> 1
    end.

%-------------------------------------------------------------------------------
% @private
% @doc process for the Source Address Mode 
% @returns a tuple containing the compressed value and the CarrInlineMap map
% @end
%-------------------------------------------------------------------------------
process_sam(SAC, SrcAdd, CarrInlineMap, CarrInlineList) when SAC == 0 ->
    SrcAddBits = <<SrcAdd:128>>,
    <<_:112, Last16Bits:16>> = SrcAddBits,
    <<_:64, Last64Bits:64>> = SrcAddBits,

    case SrcAddBits of
        <<0:128>> -> 
            {2#11,CarrInlineMap, CarrInlineList}; % the address is fully elided

        <<?LINK_LOCAL_PREFIX:16, _:48,_:24, 16#FFFE:16,_:24>> -> 
            {2#11, CarrInlineMap, CarrInlineList}; % MAC address is split into two 24-bit parts, FFFE is inserted in the middle

        <<?LINK_LOCAL_PREFIX:16, _:48, 16#000000FFFE00:48, _:16>> -> 
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"SAM"=>Last16Bits},
            %io:format("Last16Bits ~p~n",[Last16Bits]),
            {2#10, UpdatedMap, UpdatedList}; % the first 112 bits are elided, last 16 IID bits are carried in-line

        <<?LINK_LOCAL_PREFIX:16, _:48, _:64>> -> 
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"SAM"=>Last64Bits},
            {2#01, UpdatedMap, UpdatedList}; % the first 64 bits are elided, last 64 bits (IID) are carried in-line
        _ -> 
            Bin = <<SrcAdd:128>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {2#00, CarrInlineMap#{"SAM"=>SrcAdd}, UpdatedList} % full address is carried in-line
    end;

process_sam(SAC, SrcAdd, CarrInlineMap, CarrInlineList) when SAC == 1 ->
    SrcAddBits = <<SrcAdd:128>>,
    <<_:112, Last16Bits:16>> = SrcAddBits,
    <<_:64, Last64Bits:64>> = SrcAddBits,

    case SrcAddBits of
        <<0:128>> -> 
            {2#11,CarrInlineMap, CarrInlineList}; % the address is fully elided

        <<?GLOBAL_PREFIX:16, _:48, 16#000000FFFE00:48, _:16>> -> 
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"SAM"=>Last16Bits},
            %io:format("Last16Bits ~p~n",[Last16Bits]),
            {2#10, UpdatedMap, UpdatedList}; % the first 112 bits are elided, last 16 IID bits are carried in-line

        <<?GLOBAL_PREFIX:16, _:48, _:64>> -> 
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"SAM"=>Last64Bits},
            {2#01, UpdatedMap, UpdatedList}; % the first 64 bits are elided, last 64 bits (IID) are carried in-line
        _ -> 
            Bin = <<SrcAdd:128>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {2#00, CarrInlineMap#{"SAM"=>SrcAdd}, UpdatedList} % full address is carried in-line
    end.

%-------------------------------------------------------------------------------
% @private
% @doc process for the Multicast compression 
% @returns the compressed value
% @end
%-------------------------------------------------------------------------------
process_m(DstAdd) ->
    <<Prefix:16, _/binary>> = <<DstAdd:128>>,
    case Prefix of
        16#FF00 -> 1; % DstAdd is a multicast address
        16#FF02 -> 1; % DstAdd is a multicast address
        _ -> 0
    end.

%-------------------------------------------------------------------------------
% @private
% @doc process for the Destination Address Compression 
% @returns the compressed value
% @end
%-------------------------------------------------------------------------------
process_dac(DstAdd) ->
    <<Prefix:16, _/binary>> = <<DstAdd:128>>,

    case Prefix of
        16#FE80 -> 0; % link-local
        % multicast addresses
        16#FF01 -> 0;
        16#FF02 -> 0;
        16#FF03 -> 0;
        16#FF04 -> 0;
        16#FF05 -> 0; 
        16#FF06 -> 0;
        16#FF07 -> 0;
        16#FF08 -> 0;
        16#FF09 -> 0;
        16#FF0A -> 0;
        16#FF0B -> 0;
        16#FF0C -> 0;
        16#FF0D -> 0;
        16#FF0E -> 0; 
        16#FF0F -> 0;
        16#0000 -> 0; % can be elided
        16#2001 -> 1; 
        16#FD00 ->1; 
        _ -> 1
    end.

%-------------------------------------------------------------------------------
% @private
% @doc process for the Destination Address Mode
% @param DAC, M, DstAdd, CarrInlineMap
% @returns a tuple containing the compressed value and the CarrInlineMap map
% @end
%-------------------------------------------------------------------------------
process_dam(0, 0 , DstAdd, CarrInlineMap, CarrInlineList) ->
    DestAddBits = <<DstAdd:128>>,
    <<_:112, Last16Bits:16>> = DestAddBits,
    <<_:64, Last64Bits:64>> = DestAddBits,
    
    case DestAddBits of
        <<?LINK_LOCAL_PREFIX:16, 0:112>> -> 
            {2#11, CarrInlineMap, CarrInlineList}; % the address is fully elided
        <<?LINK_LOCAL_PREFIX:16, 0:48,_:24, 16#FFFE:16,_:24>> -> 
            {2#11, CarrInlineMap, CarrInlineList}; % MAC address is split into two 24-bit parts, FFFE is inserted in the middle
        <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, _:16>> -> 
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"DAM"=>Last16Bits},
            {2#10, UpdatedMap, UpdatedList}; % the first 112 bits are elided, last 16 bits are in-line
        <<?LINK_LOCAL_PREFIX:16, _:112>> -> 
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"DAM"=>Last64Bits},
            {2#01, UpdatedMap, UpdatedList}; % the first 64 bits are elided, last 64 bits are in-line
        _ -> 
            Bin = <<DstAdd:128>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {2#00, CarrInlineMap#{"DAM"=>DstAdd}, UpdatedList} % full address is carried in-line
    end;

process_dam(0, 1, DstAdd, CarrInlineMap, CarrInlineList) ->
    DestAddBits = <<DstAdd:128>>,
    <<_:112, Last16Bits:16>> = DestAddBits,
    <<_:64, Last64Bits:64>> = DestAddBits,

    case DestAddBits of
        <<?GLOBAL_PREFIX:16, _:112>> -> 
            {2#11, CarrInlineMap, CarrInlineList}; % the address is fully elided
        <<?GLOBAL_PREFIX:16, _:48,_:24, 16#FFFE:16,_:24>> -> 
            {2#11, CarrInlineMap, CarrInlineList}; % MAC address is split into two 24-bit parts, FFFE is inserted in the middle
        <<?GLOBAL_PREFIX:16, _:48, 16#000000FFFE00:48, _:16>> -> 
            Bin = <<Last16Bits:16>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"DAM"=>Last16Bits},
            {2#10, UpdatedMap, UpdatedList}; % the first 112 bits are elided, last 16 bits are in-line
        <<?GLOBAL_PREFIX:16, _:112>> -> 
            Bin = <<Last64Bits:64>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"DAM"=>Last64Bits},
            {2#01, UpdatedMap, UpdatedList}; % the first 64 bits are elided, last 64 bits are in-line
        _ -> 
            %UpdatedList = CarrInlineList++[DstAdd],
            {2#00, CarrInlineMap, CarrInlineList} % RESERVED
    end;

process_dam(1, 0, DstAdd, CarrInlineMap, CarrInlineList)->
    DestAddBits = <<DstAdd:128>>,
    <<_:80, Last48Bits:48>> = DestAddBits,
    <<_:96, Last32Bits:32>> = DestAddBits,
    <<_:120, Last8Bits:8>> = DestAddBits,

    case DestAddBits of
        <<16#FF02:16, 0:104, _:8>> -> % ff02::00XX.
            Bin = <<Last8Bits:8>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"DAM"=>Last8Bits},
            {2#11, UpdatedMap, UpdatedList};
        <<16#FF:8, _:8, 0:80, _:32>> -> %ffXX::00XX:XXXX.
            Bin = <<Last32Bits:32>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"DAM"=>Last32Bits},
            {2#10, UpdatedMap, UpdatedList};
        <<16#FF:8, _:8, 0:64, _:48>> -> % ffXX::00XX:XXXX:XXXX.
            Bin = <<Last48Bits:48>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"DAM"=>Last48Bits},
            {2#01, UpdatedMap, UpdatedList}; 
        
        _ -> 
            Bin = <<DstAdd:128>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            {2#00, CarrInlineMap#{"DAM"=>DstAdd}, UpdatedList} % full address is carried in-line
    end; 

process_dam(1, 1, DstAdd, CarrInlineMap, CarrInlineList)->
    DestAddBits = <<DstAdd:128>>,
    <<_:80, Last48Bits:48>> = DestAddBits,
    case DestAddBits of
        <<16#FF, _:112>> ->
            Bin = <<Last48Bits:48>>,
            L = [Bin],
            UpdatedList = CarrInlineList ++ L,
            UpdatedMap = CarrInlineMap#{"DAM"=>Last48Bits},
            {2#00, UpdatedMap, UpdatedList}
    end.




%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                       Packet fragmentation
%
%------------------------------------------------------------------------------------------------------------------------------------------------------


% Fragmentation Header
build_frag_header(#frag_header{frag_type = FragType, datagram_size = DatagramSize, datagram_tag = DatagramTag, datagram_offset = DatagramOffset}) ->
    <<FragType:5, DatagramSize:11, DatagramTag:16, DatagramOffset:8>>.

% Datagram Packet
build_datagram_pckt(DtgmHeader, Payload) ->
    Header = build_frag_header(DtgmHeader),
    <<Header/bitstring, Payload/bitstring>>.

%-------------------------------------------------------------------------------
% @doc fragment an Ipv6 packet 
% @returns a list of fragmented packets 
% [{Header1, Fragment1}, ..., {HeaderN, FragmentN}]
% @end
%-------------------------------------------------------------------------------
fragment_ipv6_packet(Ipv6Pckt) when is_binary(Ipv6Pckt) ->
    DatagramTag = rand:uniform(65536), % TODO Check unicity 
    Size = bit_size(Ipv6Pckt),
    process_for_frag(Ipv6Pckt,Size, DatagramTag, 0, []).

%-------------------------------------------------------------------------------
% @private
% @doc helper function to process the received packet
% @returns a list of fragmented packets 
% [{Header1, Fragment1}, ..., {HeaderN, FragmentN}]
% Input : 
%   Ipv6Pckt := binary
%   Pckt size := integer
%   DatagramTag := integer
%   Offset := integer
%   Accumulator : list  
% @end
%-------------------------------------------------------------------------------
process_for_frag(<<>>,_, _, _, Acc) ->
    lists:reverse(Acc);

process_for_frag(Ipv6Pckt, Size, DatagramTag, Offset, Acc) ->
    MaxSize = ?MAX_FRAME_SIZE - ?FRAG_HEADER_SIZE,
    FragmentSize = min(byte_size(Ipv6Pckt), MaxSize),
    <<Fragment:FragmentSize/binary, Rest/binary>> = Ipv6Pckt,
    Header = build_frag_header(#frag_header{
        frag_type = if Offset == 0 -> ?FRAG1_DHTYPE; true -> ?FRAGN_DHTYPE end,
        datagram_size = Size,% + Offset,
        datagram_tag = DatagramTag,
        datagram_offset = Offset
    }),
    process_for_frag(Rest, Size, DatagramTag, Offset + 1, [{Header, Fragment} | Acc]).


%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                           Header Decompression
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

%get_prefix(ContextId) ->
%    maps:get(ContextId, ?CONTEXT_TABLE).
decompress_ipv6_header(CompressedPacket, EUI64) ->
    <<TF:8, NH:8, HLIM:8, CID:8, SAC:8, SAM:8, M:8, DAC:8, DAM:8, Rest/binary>> = CompressedPacket,
    % Rest contain carriedInline values + payload 
    CompressedHeader = {TF, NH, HLIM, CID, SAC, SAM, M, DAC, DAM},
    %io:format("CompressedHeader: ~p~n", [CompressedHeader]),
    %MacIID = get_iid_from_mac(EUI64),
    % RestN represents the CarriedInline with field of interest 
    {TrafficClass, FlowLabel, Rest1} = decode_tf(TF, Rest), 
    {NextHeader,Rest2}  = decode_next_header(NH, Rest1),
    {HopLimit,Rest3} = decode_hlim(HLIM, Rest2),
    {SourceAddress,Rest4} = decode_sam(SAC, SAM, Rest3,EUI64),
    {DestAddress,Payload} = decode_dam(M, DAC, DAM, Rest4,EUI64),
    PayloadLength = bit_size(Payload),
    DecompressedFields = {TrafficClass, FlowLabel, PayloadLength, NextHeader, HopLimit,SourceAddress,DestAddress, Payload}, 
    
    io:format("DecompressedFields ~p~n", [DecompressedFields]),
    DecompressedPckt = tuple_to_bin(DecompressedFields),
    DecompressedPckt.
    %{TrafficClass, FlowLabel, NextHeader, HopLimit, SourceAddress, DestAddress, Payload}.

decode_tf(TF, CarriedInline) ->
    % retrieve values of interest from Rest 
    % TODO, check max value on 20bits for FL, and infer bit split
    % TODO - compute binary size of 
    <<TrafficClass:8, FL1:8, FL2:8,FL3:8, Rest/binary>> = CarriedInline,

    FlowLabel = <<FL1,FL2,FL3>>,

     case TF of
        2#11 -> % everything elided
            {<<0:8>>, <<0:20>>, CarriedInline};

        2#10 -> % Flow Label is elided, retrieve TF value carriedInline => get first 8bit of CarriedInline 
            {TrafficClass,<<0:20>>, Rest};

        2#01 -> % only DSCP is elided
            {TrafficClass,FlowLabel, Rest};
            
        2#00 -> % nothing elided
            %io:format("FlowLabel: ~p~n",[FlowLabel]),
            {TrafficClass,FlowLabel, Rest}
    end.

decode_next_header(NH, CarriedInline) when NH == 0 ->
    <<NextHeader:8, Rest/binary>> = CarriedInline,
    {NextHeader, Rest}; 
decode_next_header(NH, CarriedInline) when NH == 1 -> % decompressed usig LOWPAN_NHC
    {0, CarriedInline}.

decode_hlim(NH, CarriedInline) ->
    <<HopLimit:8, Rest/binary>> = CarriedInline,
     case NH of
        2#11 -> {255, CarriedInline};
        2#10 -> {64, CarriedInline};
        2#01 -> {1, CarriedInline};
        2#00 -> {HopLimit, Rest}
    end.

decode_sam(SAC, SAM, CarriedInline, MacIID) when SAC == 0 ->
     case SAM of
        2#11 -> 
            % TODO the last 64bits should be computed from the encapsulating header as shown in section 3.2.2 from rfc6282
            <<_,_,_,_,_,_,G,H>> = MacIID,
            IID = <<G,H>>,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48,16#000000FFFE00:48,IID/binary>>,
            {SrcAdd, CarriedInline};
        2#10 -> % last 16bits carried
            %<<Last16Bits:16, Rest/binary>> = CarriedInline,
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A,B>>,
            SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48,16#000000FFFE00:48,Last16Bits/binary>>,
            {SrcAdd, Rest};
        2#01 -> % last 64bits carried
            %<<Last64Bits:64, Rest/binary>> = CarriedInline,
            <<A:8, B:8,C:8,D:8,E:8,F:8,G:8, H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A,B,C,D,E,F,G,H>>,
             SrcAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, Last64Bits/binary>>,
            {SrcAdd, Rest};
        2#00 -> % full add carried
            <<A:8, B:8,C:8,D:8,E:8,F:8,G:8, H:8,A2:8, B2:8,C2:8,D2:8,E2:8,F2:8,G2:8, H2:8, Rest/binary>> = CarriedInline,
            SrcAdd = <<A,B,C,D,E,F,G,H,A2,B2,C2,D2,E2,F2,G2,H2>>,
            %<<SrcAdd:128, Rest/binary>> = CarriedInline,
            {SrcAdd, Rest}
    end; 

decode_sam(SAC, SAM, CarriedInline, MacIID) when SAC == 1->
    case SAM of
        2#11 -> 
            % TODO the last 64bits should be computed from the encapsulating header as shown in section 3.2.2 from rfc6282
            <<_,_,_,_,_,_,G,H>> = MacIID,
            IID = <<G,H>>,
            SrcAdd = <<?GLOBAL_PREFIX:16, 0:48,16#000000FFFE00:48,IID/binary>>,
            {SrcAdd, CarriedInline};
        2#10 -> % last 16bits carried
            %<<Last16Bits:16, Rest/binary>> = CarriedInline,
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A,B>>,
            SrcAdd = <<?GLOBAL_PREFIX:16, 0:48,16#000000FFFE00:48,Last16Bits/binary>>,
            {SrcAdd, Rest};
        2#01 -> % last 64bits carried
            %<<Last64Bits:64, Rest/binary>> = CarriedInline,
            <<A:8, B:8,C:8,D:8,E:8,F:8,G:8, H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A,B,C,D,E,F,G,H>>,
             SrcAdd = <<?GLOBAL_PREFIX:16, 0:48, Last64Bits/binary>>,
            {SrcAdd, Rest};
        2#00 -> % full add carried
            <<A:8, B:8,C:8,D:8,E:8,F:8,G:8, H:8,A2:8, B2:8,C2:8,D2:8,E2:8,F2:8,G2:8, H2:8, Rest/binary>> = CarriedInline,
            SrcAdd = <<A,B,C,D,E,F,G,H,A2,B2,C2,D2,E2,F2,G2,H2>>,
            %<<SrcAdd:128, Rest/binary>> = CarriedInline,
            {SrcAdd, Rest}
    end.


decode_dam(0, DAC, DAM, CarriedInline, MacIID) when DAC == 0->
    case DAM of
        2#11 -> {<<?LINK_LOCAL_PREFIX:16, 0:112>>, CarriedInline};
        2#10 -> % last 16bits carried
            %<<Last16Bits:16, Rest/binary>> = CarriedInline,
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A,B>>,
            DstAdd =  <<?LINK_LOCAL_PREFIX:16, 0:48, 16#000000FFFE00:48, Last16Bits/binary>>,
            {DstAdd, Rest};
        2#01 -> % last 64bits carried
            %<<Last64Bits:64, Rest/binary>> = CarriedInline,
            <<A:8, B:8,C:8,D:8,E:8,F:8,G:8, H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A,B,C,D,E,F,G,H>>, 
            DstAdd = <<?LINK_LOCAL_PREFIX:16, 0:48, Last64Bits/binary>>,
            {DstAdd, Rest};
        2#00 -> % full add carried
            %<<DstAdd:128, Rest/binary>> = CarriedInline,
            <<A:8, B:8,C:8,D:8,E:8,F:8,G:8, H:8,A2:8, B2:8,C2:8,D2:8,E2:8,F2:8,G2:8, H2:8, Rest/binary>> = CarriedInline,
            DstAdd = <<A,B,C,D,E,F,G,H,A2,B2,C2,D2,E2,F2,G2,H2>>,
            {DstAdd, Rest}
    end;

decode_dam(0, DAC, DAM, CarriedInline, MacIID) when DAC == 1->
    case DAM of
        2#11 -> {<<?GLOBAL_PREFIX:16, 0:112>>, CarriedInline};
        2#10 -> % last 16bits carried
            %<<Last16Bits:16, Rest/binary>> = CarriedInline,
            <<A:8, B:8, Rest/binary>> = CarriedInline,
            Last16Bits = <<A,B>>,
            DstAdd =  <<?GLOBAL_PREFIX:16, 0:48, 16#000000FFFE00:48, Last16Bits/binary>>,
            {DstAdd, Rest};
        2#01 -> % last 64bits carried
            %<<Last64Bits:64, Rest/binary>> = CarriedInline,
            <<A:8, B:8,C:8,D:8,E:8,F:8,G:8, H:8, Rest/binary>> = CarriedInline,
            Last64Bits = <<A,B,C,D,E,F,G,H>>, 
            DstAdd = <<?GLOBAL_PREFIX:16, 0:48, Last64Bits/binary>>,
            {DstAdd, Rest};
        2#00 -> {error_reserved, CarriedInline}
    end;


decode_dam(1, DAC, DAM, CarriedInline, MacIID) when DAC == 0->
    case DAM of
        2#00 -> {<<0:128>>, CarriedInline};
        2#01 -> % last 48bits carried
            %<<Last48Bits:48, Rest/binary>> = CarriedInline,
            <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, Rest/binary>> = CarriedInline,
            Last48Bits = <<C,D,E,F, G, H>>,
            io:format("Last48Bits ~p~n",[Last48Bits]), %TODO retrieve correct size
            DstAdd = <<16#FF02:16,0:64, Last48Bits/binary>>,
            {DstAdd, Rest};
        2#10 -> % last 32bits carried
            %<<Last32Bits:32, Rest/binary>> = CarriedInline,
            <<A:8, B:8,C:8, D:8, Rest/binary>> = CarriedInline,
            Last32Bits = <<A,B,C,D>>,
            DstAdd = <<16#FF02:16, 0:80, Last32Bits/binary>>,
            {DstAdd, Rest};
        2#11 -> % last 8bits carried
            <<Last8Bits:8, Rest/binary>> = CarriedInline,
            DstAdd = <<16#FF02:16, 0:104, Last8Bits>>,
            {DstAdd, Rest}
    end;

decode_dam(1, DAC, DAM, CarriedInline, MacIID) when DAC == 1->
    case DAM of
        2#00 -> % last 48bits carried
            %<<Last48Bits:48, Rest/binary>> = CarriedInline,
            <<A:8, B:8, C:8, D:8, E:8, F:8, Rest/binary>> = CarriedInline,
            Last48Bits = <<A,B,C,D,E,F>>,
            DstAdd = <<16#FF, 0:64, Last48Bits/binary>>,
            {DstAdd, Rest}
    end.


%------------------------------------------------------------------------------------------------------------------------------------------------------
%                                                           Packet Decompression Helper
%------------------------------------------------------------------------------------------------------------------------------------------------------
get_iid_from_mac(MacAdd) ->
    %io:format("Received mac add: ~p~n", [MacAdd]),
    <<A1:8, A2:8, A3:8, A4:8, A5:8, A6:8>> = MacAdd,
    Mask = 2#00000010,
    ULBLit = A1 bxor Mask, % Invert 7th bit
    %io:format("Before: ~p~nAfter: ~p~n", [MacAdd,ULBLit]),
    IID = <<ULBLit:8, A2:8, A3:8, 16#FF:8, 16#FE:8, A4:8, A5:8, A6:8>>,
    %io:format("Result: ~p~n", [IID]),
    IID.

get_default_LL_add(MacAdd)->
    %IID = get_iid_from_mac(MacAdd), %TODO verify correctness
    LLAdd = <<16#FE80:16, 0:48,MacAdd/binary>>,
    %io:format("LLAdd: ~p~n", [LLAdd]),
    LLAdd.

tuple_to_bin(Tuple) ->
    Elements = tuple_to_list(Tuple),
    Binaries = [element_to_binary(Elem) || Elem <- Elements],
    list_to_binary(Binaries).

element_to_binary(Elem) when is_integer(Elem) ->
   encode_integer(Elem);
element_to_binary(Elem) when is_binary(Elem) ->
    Elem;
element_to_binary(Elem) when is_tuple(Elem) ->
    tuple_to_bin(Elem);
element_to_binary(Elem) when is_list(Elem) ->
    list_to_binary(Elem).


%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                         FROM Mac layer to 6LoWPAN
%
%------------------------------------------------------------------------------------------------------------------------------------------------------

build_mesh_header(MeshHeader)->
    #mesh_header{
        mesh_type = MeshType, v_bit = VBit, f_bit = FBit, hops_left = HopsLeft,
        originator_address = OriginatorAddress, final_destination_address = FinalDestinationAddress
    } = MeshHeader,

    <<MeshType:2, VBit:1, FBit:1, HopsLeft:4, OriginatorAddress:16,FinalDestinationAddress:16>>.





%------------------------------------------------------------------------------------------------------------------------------------------------------
%
%                                                               Reassembly
%
%------------------------------------------------------------------------------------------------------------------------------------------------------


% upon receive fragment event: 
% - start timer
% - start counter = counter+receive frag size, stop when counter = datagram_orig_size
% - from header, add payload and offset to a map tag => {offset, payload}
% if timout, discard datagram => remove it from map 

%-------------------------------------------------------------------------------
% @doc helper function to retrieve datagram info 
% @returns a tuple containing useful datagram fields
% @end
%-------------------------------------------------------------------------------
datagram_info(Fragment)->
    <<FragType:5, DatagramSize:11, DatagramTag:16, DatagramOffset:8, Payload/binary>> = Fragment,
    {FragType, DatagramSize, DatagramTag, DatagramOffset, Payload}.

start_reassembly_timer(DatagramTag, Map)->
    erlang:send_after(?REASSEMBLY_TIMEOUT, self(), {timeout, DatagramTag, Map}).

%-------------------------------------------------------------------------------
% @doc launch the reassembly process
% @param Fragments: list [{Header1, Fragment1}, ..., {HeaderN, FragmentN}]
% @returns the reassembled ipv6 packet
% @end
%-------------------------------------------------------------------------------
reassemble_datagrams(Fragments) when is_list(Fragments)->
    [FirstFragment | _] = Fragments, 
    {_, Size, Tag, _, _} = lowpan:datagram_info(FirstFragment),

    Datagram = #datagram{tag = Tag, size = Size},
    DatagramMap = maps:put(Tag, Datagram, ?DATAGRAMS_MAP), % add retrieve info to the datagram map 

    {ReassembledPacket, _NewMap} = process_fragments(Fragments, DatagramMap, undefined),
    ReassembledPacket.



%-------------------------------------------------------------------------------
% @doc launch the reassembly process for a single fragment
% @param Fragment: single Fragment
% @param DatagramMap: the current state of the datagram map
% @returns a tuple containing the reassembled packet (if complete) or the atom
%          `notYetReassembled` and the updated DatagramMap
% @end
%-------------------------------------------------------------------------------
reassemble_datagram(Fragment, DatagramMap) ->
    {_, Size, Tag, _, _} = lowpan:datagram_info(Fragment),

    case maps:find(Tag, DatagramMap) of
        {ok, _} ->
            process_fragment(Fragment, DatagramMap);
        error ->
            % first fragment
            Datagram = #datagram{tag = Tag, size = Size},
            UpdatedMap = maps:put(Tag, Datagram, DatagramMap),
            process_fragment(Fragment, UpdatedMap)
    end.


%-------------------------------------------------------------------------------
% @private
% @doc helper function for the reassembly process  
% @returns a tuple containing the reassembled packet and the final DatagramMap state
% @end
%-------------------------------------------------------------------------------
process_fragments([], Map, ReassembledPacket)->
    {ReassembledPacket, Map};  % when the list is empty, returns the last payload and the final map state

process_fragments([HeadFrag | TailFrags], DatagramMap, _Payload)->
    {ReassembledPacket, UpdatedMap} = process_fragment(HeadFrag, DatagramMap),
    process_fragments(TailFrags, UpdatedMap, ReassembledPacket).

%-------------------------------------------------------------------------------
% @private
% @doc process the first fragment, launch timer, and add it to the DatagramMap  
% the reassembly if last fragment is received 
% @end
%-------------------------------------------------------------------------------
process_fragment(<<?FRAG1_DHTYPE:5, Size:11, Tag:16, Offset:8, Payload/binary>>, Map) ->
    NewFragment = #{Offset => Payload},
    CurrSize = bit_size(Payload),
    Datagram = #datagram{tag = Tag, size = Size, cmpt=CurrSize, fragments = NewFragment},
    UpdatedMap = maps:put(Tag, Datagram, Map),
    case CurrSize == Size of
        true ->
            ReassembledPacket = reassemble(Tag, UpdatedMap),
            {ReassembledPacket, UpdatedMap};
        false ->
            {notYetReassembled, UpdatedMap}
    end;

%-------------------------------------------------------------------------------
% @private
% @doc process the subsequent fragments, add them to the DatagramMap and launch
% the reassembly if last fragment is received 
% @end
%-------------------------------------------------------------------------------

process_fragment(<<?FRAGN_DHTYPE:5, Size:11, Tag:16, Offset:8, Payload/binary>>, Map) ->
    case maps:find(Tag, Map) of
        {ok, OldDatagram} ->
            CurrSize = bit_size(Payload),
            UpdatedCmpt = OldDatagram#datagram.cmpt + CurrSize, % update size cmpt
            FragmentsMap = OldDatagram#datagram.fragments, % get fragmentMap
            NewFragments = FragmentsMap#{Offset => Payload}, % put new fragment to fragmentMap
            UpdatedDatagram = OldDatagram#datagram{cmpt = UpdatedCmpt, fragments = NewFragments}, % update datagram
            UpdatedMap = maps:put(Tag, UpdatedDatagram, Map), % update DatagramMap
            case UpdatedCmpt == Size of
                true ->
                    ReassembledPacket = reassemble(Tag, UpdatedMap),
                    {ReassembledPacket, UpdatedMap};
                false ->
                    {notYetReassembled, UpdatedMap}
                end;
        error ->
            {undefined, Map}
    end.

%-------------------------------------------------------------------------------
% @private
% @doc helper function to reassembled all received fragments based on the Tag
% @end
%-------------------------------------------------------------------------------
reassemble(Tag,UpdatedMap)->
    Datagram = maps:get(Tag, UpdatedMap),
    FragmentsMap = Datagram#datagram.fragments,
    % sort fragments by offset and extract the binary data
    SortedFragments = lists:sort([ {Offset, Fragment} || {Offset, Fragment} <- maps:to_list(FragmentsMap) ]),
    % concatenate the fragments
    ReassembledPacket = lists:foldl(fun({_Offset, Payload}, Acc)-> 
                                        <<Acc/binary, Payload/binary>> % append new payload to the end   
                                    end, <<>>, SortedFragments), %% <<>> is the initial value of the accumulator
    discard_datagram(Tag,UpdatedMap), % discard tag so it can be reused
    ReassembledPacket.


discard_datagram(Tag, Map)->
    maps:remove(Tag,Map).

%discard_fragment(Offset, Fragments)->
%    maps:remove(Offset,Fragments).


%-------------------------------------------------------------------------------
% @private
% @doc helper function to discard stored fragments when timer exceed the limit
% @end
%-------------------------------------------------------------------------------
%duplicate_frag(Offset, Datagram)->
%    Fragments = Datagram#datagram.fragments,
%    case maps:is_key(Offset, Fragments) of
%        true-> true;
%        false-> false
%    end.