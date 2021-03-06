## Install

See the [Github page](https://github.com/joshland/wgmesh) for current release docs.

## Requirements

 - [Fedora](https://getfedora.org/en/server/#:~:text=Fedora%20Server%20is%20a%20short,in%20the%20open%20source%20community.) _prolly any modern linux will work_
 - [Wireguard](https://www.wireguard.com/) _included with Fedora (wireguard-tools)_
 - [Python](https://www.python.org/) _included with almost all modern linux_
 - [BIRD](https://bird.network.cz/) _modular protocol routing daemon_
 - [Shorewall](https://shorewall.org/) _local linux firewall configuration, with the simple two-interface setup_

## Coordinator

A machine will be needed to setup the mesh itself, and manage the nodes and configuration messages. This can be hosted on a node.

This can be a laptop or a server with a shell account somewhere.

## Endpoints (Nodes)

Routing nodes are minimalist, and should have an inbound and an outbound interface.  The reference configuration is Virutal Machines with a public and a private (or trusted) network card.

The `wgconfig` script configures this.

 - Inbound: internet-facing interface.
 - Outbound: (Advanced Config Only) internal Veth used to move traffic between namespaces.
 - Trust: inside-facing interface. You wil have to configure this

 ## Basic Setup

 vpn-nodea
    - Inbound: eth0, 1.1.1.1
    - Trust: eth1, 10.1.1.1/24

 vpn-nodeb
    - Inbound: eth0, 2.2.2.2
    - Trust: eth1, 192.168.1.1/24

We'll put the Coordinator on vpn-nodea under the "admin" account:

    (admin) [admin@vpn-nodea ~]$ pip install pip wheel
    Requirement already satisfied: pip in ./lib/python3.8/site-packages (19.3.1)
    Collecting wheel
    Downloading https://files.pythonhosted.org/packages/65/63/39d04c74222770ed1589c0eaba06c05891801219272420b40311cd60c880/wheel-0.36.2-py2.py3-none-any.whl
    Installing collected packages: wheel
    Successfully installed wheel-0.36.2
    WARNING: You are using pip version 19.3.1; however, version 21.0.1 is available.
    You should consider upgrading via the 'pip install --upgrade pip' command.
    (admin) [admin@vpn-nodea ~]$ pip install wgmesh
    Collecting wgmesh
    Requirement already satisfied: wheel in ./lib/python3.8/site-packages (from wgmesh==0.5.4) (0.36.2)
    Collecting attrs
    [....]

Fetch the [default wgmesh config](https://github.com/joshland/wgmesh/raw/master/wgmesh-default.yaml).

    wget https://github.com/joshland/wgmesh/raw/master/wgmesh-default.yaml


Fetch the systemd scripts:

    wget https://github.com/joshland/wgmesh/raw/master/systemd/bird%40.service
    wget https://github.com/joshland/wgmesh/raw/master/systemd/systemd-netns-access%40.service
    wget https://github.com/joshland/wgmesh/raw/master/systemd/systemd-netns%40.service
    wget https://github.com/joshland/wgmesh/raw/master/systemd/wgmesh%40.service

## Config - Copy & Edit

    #!sh
    cp wgmesh-default smesh.yaml

Example:

    #!YAML
    global:
      alerts: alerts@here.com
      domain: smesh.here.com
      ipv6: fd86:ea04:1116::/48
      # Examples: https://simpledns.plus/private-ipv6
      locus: smesh
      portbase: 21100
      asn_range: 64512:64525
      publickey: ''
      privatekey: master-smesh.key

    hosts: {}

## Site Config Test 

    wgsite smesh.yaml

Note; YAML parsing errors are confusing.  If you have such an error, resolve it.

After this, either add AWS tokens for your Route53 dns, or manually create the indicated TXT record in the DNS of your choosing.


## Node config

Download and install Shorewall.  Copy the "two-interface-sample" to /etc/shorewall.  This prepares the firewall for operation.  Do not enable it yet.

Disable firewalld

    systemctl stop firewalld
    systemctl disable firewalld
    systemctl mask firewalld


For local node config, it is easiest to install the wgmesh package or to `pip install` as root.

Note: Run the configuration tools as root. This assumes that `wireguard-tools` have been installed.

The DNS server will need to be configured and propagated:

    [root@vpn-nodea ~]# host -t txt smesh.here.com
    smesh.here.com descriptive text "0:bG9jdXM6IHNtZXNoCnB1YmxpY2tleTogSkJiZWZ0T3BEY2tLMTVGNUtrdDlFOTF1OURqSDhYc3hv"
    smesh.here.com descriptive text "1:NFRwME9HM0lYVT0K"

If that check passes, you can proceed with Configuring the node

    #!sh

    [root@vpn-nodea ~]# wgconfig -i eth0 -T eth1 -I 10.1.1.1/24 smesh.here.com
    [root@vpn-nodea ~]# wghost -a vpn-nodea.dyndns.org smesh.here.com
    2021-03-05 16:19:53.334 | WARNING  | wgmesh.hostinit:cli:163 - Hostname added, does not resolve: vpn-nodea.dyndns.org

    Message to Home: cHVibGljX2tleTogZG55MFRhSGQrZFJBTS9DNnU1VXR1RENncG1EbXFXMHhrUndONjFVRnpqbz0KbWVzc2FnZTogISFiaW5hcnkgf[.snip.]
    VWR3Q2s5UFdGZG1iMnMzT0ZsM2NtWlYKICBkelI1UzJWVVkzcG9NR05MU21Ga2VqQTlDZz09Cg==

Copy and paste this message, for import on the Coordinator

    [admin@vpn-nodea ~]$ wgsite -i "[message from client]" smesh.yaml

Observe the changes to `smesh.yaml`

    #!YAML
    global:
      alerts: alerts@here.com
      domain: smesh.here.com
      ipv6: fd86:ea04:1116::/48
      # Examples: https://simpledns.plus/private-ipv6
      locus: smesh
      portbase: 21100
      asn_range: 64512:64525
      publickey: ''
      privatekey: master-smesh.key

    hosts:
      vpn-nodea.dyndns.org:
        asn: '64512'
        local_ipv4:
        - vpn-nodea.dyndns.org
        local_ipv6:
        - ''
        local_networks: ''
        octet: '1'
        private_key_file: /etc/wireguard/smesh_priv
        public_key: dny0TaHd+dRAM/C6u5UtuDCgpmDmqW0xkRwN61UFzjo=
        public_key_file: /etc/wireguard/smesh_pub
        uuid: e0f7a4bf-94bb-44f4-9b4d-98d7910f0e9b

Repeat this step for your other node(s).

Once complete, publish the results.  Again, either use AWS Route53 or manually publish the DNS records as specified:



        |----| ## BEGIN HOST: vpn-nodea.here.com
        TXT:
        e0f7a4bf-94bb-44f4-9b4d-98d7910f0e9b.smesh.here.com

        DATA:
        (using AWS API to save changes...) 
        0:uVyr/hPKElTPsHEv0qEkOKeyXPE5mUuiq0plx9mHX42OUovf+padcOfpf2iCoS82kUAuwhJTm0yP
        [.snip.]
        10:KD/y/K7JQOfm16rj/ONrluYlvbVq1MU8Vs+IzAfWyM4FffiRd+fRbvI8XAd/FfYKjn6CXahxQYev
        11:NS6k4vU=

        |----| ## BEGIN HOST: vpn-nodeb.here.com
        TXT:
        f7ec3c91-e632-42ea-87eb-86daf80b2b4e.smesh.here.com

        DATA:
        (using AWS API to save changes...) 
        0:LTZa5HpjBpbIynvUD3S9MGieywd07TDGrtJsigBPV9oxI5LjwQZm5Mgsna1jUea07XDCJFAH9lLR
        [.snip.]
        10:ZWFHegeSsyq/LyRYPEpxnjr66gcyrd65UAMyJ/677U9gHBS0ZJCgL5SzQ9/HwBlE1di1RaC+SlSn
        11:PEqSOts=

Once these are published, return to the node, and deploy:
(Example using debug flag '-d')

        [root@vpn-nodea ~]# wgdeploy -d mesh.erickson.is
        2021-03-05 16:31:20.293 | INFO     | wgmesh.core:LoggerConfig:427 - Debug
        2021-03-05 16:31:20.318 | DEBUG    | wgmesh.core:keyimport:181 - Create KM Object key:44 / raw:32
        2021-03-05 16:31:20.318 | DEBUG    | wgmesh.core:keyimport:183 - Encoded: [message]
        2021-03-05 16:31:20.318 | DEBUG    | wgmesh.core:keyimport:181 - Create KM Object key:44 / raw:32
        2021-03-05 16:31:20.319 | DEBUG    | wgmesh.core:keyimport:183 - Encoded: [message]
        2021-03-05 16:31:20.319 | DEBUG    | wgmesh.core:keyimport:181 - Create KM Object key:44 / raw:32
        2021-03-05 16:31:20.319 | DEBUG    | wgmesh.core:keyimport:183 - Encoded:  [message]
        2021-03-05 16:31:20.426 | DEBUG    | wgmesh.deploy:check_update_file:109 - Write file: /etc/wireguard/wg1.conf
        2021-03-05 16:31:20.429 | DEBUG    | wgmesh.deploy:check_update_file:109 - Write file: /etc/wireguard/wg2.conf
        2021-03-05 16:31:20.446 | DEBUG    | wgmesh.deploy:check_update_file:109 - Write file: /etc/shorewall/rules
        2021-03-05 16:31:20.446 | DEBUG    | wgmesh.deploy:check_update_file:109 - Write file: /etc/shorewall/interfaces
        2021-03-05 16:31:20.447 | DEBUG    | wgmesh.deploy:check_update_file:109 - Write file: /usr/local/sbin/ns-private
        2021-03-05 16:31:20.448 | DEBUG    | wgmesh.deploy:check_update_file:99 - Write file: /usr/local/sbin/ns-tester, no update needed.
        2021-03-05 16:31:20.448 | DEBUG    | wgmesh.deploy:check_update_file:99 - Write file: /usr/local/sbin/mesh_wg_restart, no update needed.
        2021-03-05 16:31:20.449 | DEBUG    | wgmesh.deploy:check_update_file:99 - Write file: /etc/bird/bird_private.conf, no update needed.
        2021-03-05 16:31:20.458 | WARNING  | wgmesh.deploy:cli:310 - Failed to set ownership of /etc/bird/bird_private.conf.

Run this on all nodes.

## Systemd

Deploy the systemd files downloaded to `/etc/systemd/system`. Enable only two:

        systemctl enable bird@private wgmesh@private
    
Now, in theory, reboot, and the magic should happen.

## Monitoring

The Main namespace is where you are running all the commands.  The "private" namespace, is where the mesh is running.  If you want to inspect the network interface(s), you need to examine it. 

Bird will be running in the namespace, and you can monitor it via the UNIX Socket from anywhere:

    watch -n1 "birdc -s /var/run/bird-private.sock show prot;echo '';birdc -s /var/run/bird-private.sock show bfd session;echo '';birdc -s /var/run/bird-private.sock show route count"