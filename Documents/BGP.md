## Bird Getting Started

 - [Reference Reading cilium](https://docs.cilium.io/en/v1.9/gettingstarted/bird/)
 - [Bird Basic BGP](https://docs.netx.as/tutorials/bgp/basic-bgp.html)
 - [Bird 2.0 Usersguide](https://bird.network.cz/?get_doc&f=bird.html&v=20)
 - [Bird Filters Userguide](https://bird.network.cz/?get_doc&v=20&f=bird-5.html)
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

