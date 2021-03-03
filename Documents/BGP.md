## Bird Getting Started

 - [Reference Reading cilium](https://docs.cilium.io/en/v1.9/gettingstarted/bird/)
 - [Bird Basic BGP](https://docs.netx.as/tutorials/bgp/basic-bgp.html)
 - [Bird 2.0 Usersguide](https://bird.network.cz/?get_doc&f=bird.html&v=20)
 - [Bird Filters Userguide](https://bird.network.cz/?get_doc&v=20&f=bird-5.html)
 - [NaNOG Presentation](https://archive.nanog.org/meetings/nanog48/presentations/Monday/Filip_BIRD_final_N48.pdf)


## BIRD Show Route Output

BIRD imitates Juniper, for the most part.  [Juniper Docs](
https://www.juniper.net/documentation/en_US/junos/topics/reference/command-summary/show-route-output.html) document the majority of the `show route` command.

[This BIRD ML Thread](https://bird.network.cz/pipermail/bird-users/2019-March/013144.html) discusses where the two are different.

Notably:

 - `!` is used to indicate routes which failed to push into the kernel table.
 - OSPF Triplets are `protocol preference / OSPF distance / OSPF external distance`

    ***Note though that the preference value in bird is inverted compared to
    Cisco which uses administrative distance. Juniper seems to use the term
    preference value but have the same semantics as Cisco administrative
    distance.***

    ***Bird preference value: higher is more preferred***
    ***Cisco/Juniper AD value: lower is more preferred***

 - OSPF Routes with a double (xx/xx) indicates `protocol preference / OSPF distance`

## Routing Speed

Update (2018-01)

    Intel also recommends disabling all power optimizations, notably frequency scaling (cpupower frequency-set -g performance) and turbo mode functionalities (echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo) as the TSC is independent of the frequency.

## Link Setup

    #!/bin/bash
    #
    #

    ## NS Creation
    ip netns add private

    ## Add ens3
    ip link set netns private dev ens3
    ip netns exec private ip addr add 172.16.143.22/24 dev ens3

    ## Enable Routing
    ip netns exec private sysctl -qw net.ipv6.conf.all.forwarding=1
    ip netns exec private sysctl -qw net.ipv4.conf.all.forwarding=1

    ## Start Private Routing Daemon
    ip netns exec 

    ## Start Wireguard
    ip netns exec private wg-quick up wg0
    ip netns exec private wg-quick up wg1

