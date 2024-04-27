#!/bin/bash

BASEPATH=/home/joshua/_git/wgmesh/tests

TESTNET01=192.0.2.0/24
TESTNET02=198.51.100.0/24
TESTNET03=203.0.113.0/24

function wg_config(){
    WGM_CONFIG=${BASEPATH}/${1}
    HOST=${1}
    IPV4=${2}
    IPV6=${3}
    PRIVATE=${4}

    echo "============ CONFIGURE: [${HOST}] =========================================="
    mkdir ${WGM_CONFIG} &> /dev/null
    wgsetup init example example.dyn.ashbyte.com ${WGM_CONFIG} --hostname ${HOST}.ashbyte.com --force
    wgsetup config example example.dyn.ashbyte.com ${WGM_CONFIG} --public-addrs ${IPV4},${IPV6} --trust-addrs ${PRIVATE}
    wgsetup config example example.dyn.ashbyte.com ${WGM_CONFIG} --public-iface ens1 --trust-iface ens0
    return
}

function wg_publish(){
    WGM_CONFIG=${BASEPATH}/${1}
    HOSTFILE=${WGM_CONFIG}/${1}-registration.txt
    shift
    wgsetup publish example example.dyn.ashbyte.com ${WGM_CONFIG} --outfile ${HOSTFILE} $*
}

function wg_import(){
    WGM_CONFIG=dev
    TESTPATH=${BASEPATH}/${1}
    HOSTFILE=${TESTPATH}/${1}-registration.txt
    echo "===================== HOST IMPORT [${HOSTFILE}] ==========================="
    echo "wgsite host example ${HOSTFILE} --config-path ${WGM_CONFIG} --debug"
    wgsite addhost example ${HOSTFILE} --config-path ${WGM_CONFIG} --trace
}

wg_config wgtest01 192.0.2.1       fd86:ea04:1116:1::1 172.16.142.1
wg_config wgtest02 198.51.100.2    fd86:ea04:1116:2::2 172.16.142.2
wg_config wgtest03 203.0.113.3     fd86:ea04:1116:3::3 172.16.142.3

for x in 1 2 3; do
    wg_publish wgtest0${x} --force --trace
    done

for x in 1 2 3; do
    wg_import wgtest0${x}
    done


