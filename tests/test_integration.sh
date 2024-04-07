#!/bin/bash

BASEPATH=/home/joshua/_git/wgmesh/tests

TESTNET01=192.0.2.0/24
TESTNET02=198.51.100.0/24
TESTNET03=203.0.113.0/24

function wg_config(){
    export WGM_CONFIG=${BASEPATH}/${1}
    export HOST=${1}
    export IPV4=${2}
    export IPV6=${3}
    export PRIVATE=${4}

    mkdir ${WGM_CONFIG} &> /dev/null
    wgsetup init example example.dyn.ashbyte.com ${WGM_CONFIG} --hostname ${HOST}.ashbyte.com --force
    wgsetup config example example.dyn.ashbyte.com ${WGM_CONFIG} --public-addrs ${IPV4},${IPV6} --trust-addrs ${PRIVATE}
    wgsetup config example example.dyn.ashbyte.com ${WGM_CONFIG} --public-iface ens1 --trust-iface ens0
    return
}

function wg_publish(){
    export WGM_CONFIG=${BASEPATH}/${1}
    wgsetup publish example example.dyn.ashbyte.com ${WGM_CONFIG}
}
wg_config wgtest01 192.0.2.1       fd86:ea04:1116:1::1 172.16.142.1
wg_config wgtest02 198.51.100.2    fd86:ea04:1116:2::2 172.16.142.2
wg_config wgtest03 203.0.113.3     fd86:ea04:1116:3::3 172.16.142.3

wg_publish wgtest01
wg_publish wgtest02
wg_publish wgtest03

