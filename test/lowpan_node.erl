-module(lowpan_node). 

-include_lib("common_test/include/ct.hrl").
%-include("../src/lowpan.hrl").
-include("../src/ieee802154.hrl"). 

-export([boot_network_node/0, stop_network_node/2, boot_lowpan_node/4, boot_lowpan_node/5, stop_lowpan_node/2,
            boot_node/1, get_project_cwd/0]).

-define(ROBOT_LIB_DIR, "/_build/default/lib").
%-type mac_address_type() :: mac_short_address | mac_extended_address.
%-type mac_address() :: <<_:16>> | <<_:64>>.


%% @private
%% @doc Gets the working directory of the project
-spec get_project_cwd() -> string().
get_project_cwd() -> 
    {ok, Path} = file:get_cwd(),
    filename:dirname(filename:dirname(filename:dirname(filename:dirname(Path)))).


%% @private
%% @doc Boots a remote node using the code of the project
-spec boot_node(Name) -> {pid(), node()} when
      Name :: atom().
boot_node(Name) ->
    ProjectCWD = get_project_cwd(),
    %Flags = ["-pa", ProjectCWD ++ ?ROBOT_REL_DIR ++ "/lib/robot-0.1.0/ebin"],
    Flags = ["-pa", ProjectCWD ++ ?ROBOT_LIB_DIR ++ "/robot/ebin"],
    {ok, Pid, NodeName} = ?CT_PEER(#{name => Name, args => Flags}),
    unlink(Pid),
    {Pid, NodeName}.


%% @doc Boot the network simulation node
%% This node is necessary to simulate the real UWB physical network
%% At startup, the mock_phy_network register themselves to the network to receive the tx frames
%-spec boot_network_node() -> node().
boot_network_node() ->
    {Pid, NetworkNodeName} = boot_node(network),
    erpc:call(NetworkNodeName, network_simulation, start, [{}, {}]),
    ping_node(network_loop, NetworkNodeName),
    {Pid, NetworkNodeName}.


%% @private
%% @doc Pings a remote node and wait for a 'pong' answer
%% This can be used to check if the node has been correctly started -spec ping_node(ResiteredName, Node) -> ok | error when ResiteredName :: atom(), Node          :: pid().
ping_node(RegisteredName, Node) ->
    register(pingProcess, self()),
    {RegisteredName, Node} ! {ping, pingProcess, node()},
    receive pong -> ct:pal("Node: ~p says pong", [Node])
    after 2000 -> error(network_node_not_started)
    end,
    unregister(pingProcess).


%% @doc Stops the network node
%% This function stops the network process and then stops the node
%-spec stop_network_node(Network, NetPid) -> ok when Network :: node(), NetPid  :: pid().
stop_network_node(Network, NetPid) ->
    erpc:call(Network, network_simulation, stop, [{}]),
    peer:stop(NetPid).


%% @doc Boots a node, initialize a 6lowpan stack inside
%-spec boot_lowpan_node(Name, Network, MacAddressType, MacAddress, Callback) -> {pid(), node()}.
boot_lowpan_node(Name, Network, SrcMacAddress, DstMacAddress) ->
    boot_lowpan_node(Name, Network, SrcMacAddress, DstMacAddress, fun()->ok end).

boot_lowpan_node(Name, Network, SrcMacAddress, DstMacAddress, Callback) ->
    %% TODO assign default IPv6 address from mac address 
    %lowpan:get_iid_from_mac(SrcMacAddress)
    {Pid, Node} = boot_node(Name),
    init_network_layers(Node, Network, mac_extended_address, SrcMacAddress, DstMacAddress, Callback),
    erpc:call(Node, lowpan_stack, start, [#{src_mac_addr => SrcMacAddress}]),
    {Pid, Node}.

%% Helper Function
%% @doc Initialize network layers for a node
%-spec init_network_layers(Node, Network, MacAddressType, MacAddress, Callback) -> ok.
init_network_layers(Node, Network, MacAddressType, SrcMacAddress, DstMacAddress, Callback) ->
    erpc:call(Node, mock_phy_network, start, [spi2, #{network => Network,  src_mac_addr=> SrcMacAddress,
                 dest_mac_addr => DstMacAddress}]), % start phy_net mockup
    erpc:call(Node, ieee802154, start, [#ieee_parameters{phy_layer = mock_phy_network, duty_cycle = duty_cycle_non_beacon, input_callback = Callback }]),
    set_mac_address(Node, MacAddressType, SrcMacAddress).

%% @doc Sets the MAC address based on type
%-spec set_mac_address(Node, MacAddressType, MacAddress) -> ok.
set_mac_address(Node, mac_extended_address, MacAddress) ->
    erpc:call(Node, ieee802154, set_mac_extended_address, [MacAddress]);
set_mac_address(Node, mac_short_address, MacAddress) ->
    erpc:call(Node, ieee802154, set_mac_short_address, [MacAddress]).


%% @doc Stops a 6lowpan node
%% @doc Stops a IEEE 802.15.4 node
%-spec stop_lowpan_node(Node, NodePid) -> ok.
stop_lowpan_node(Node, NodePid) ->
    %erpc:call(Node, ieee802154, stop, []),
    %erpc:call(Node, mock_phy_network, stop, []),
    erpc:call(Node, lowpan_stack, stop, []),
    peer:stop(NodePid).

%% @private

