# Create the MESH site file

        global:
          # not used
          alerts: (email address)
          # site domain name, eg. mesh01.example.com
          domain: mesh01.example.com
          # if you require local ipv4 in the wireguard tunnels (not recommended)
          #local_ipv4: 172.16.42.0/24
          # Find a suitable ipv6 for your tunnels
          local_ipv6: fd86:ea04:1116::/64
          # Examples: https://simpledns.plus/private-ipv6
          # This name is used in various way, naming keys, and other coordinating events
          # it will be publish in base64 messages in dns
          locus: wgmesh
          # the base port for all your nodes.
          portbase: 21100
          # List of BGP asns for use - example is 16bit, but 32bit ASNs are ok
          asn_range: 64512:64525
          # This should be autofilled
          publickey: ''
          # Generate a key, using wgkeys
          privatekey: site.key
          ## Optional:
          # route53 zone-id
          route53: Z1A0W32GFVM2RH
          # 
          aws_access_key_id: <access key>
          aws_secret_access_key: <secret key>
        # empty hashmap, used by wgsite -i
        hosts: {}

### Publish the site

        site-mgr$ wgsite <config.yaml>

Check your DNS registration.

        site-mgr$ host -t txt mesh01.example.com

Nothing else works, if we don't have the TXT records in dns. It publishes your site public key, and your 
common locus.

### Configure your first host

On your host, install the wgmesh package in a venv. 

Configure your local details:

        vpn-nodea$ wgconfig -dt -i enp1s0 -T enp8s0 -I 10.12.1.12/24 mesh01.example.com

- Fetches the site key and the locus from dns
- creates a site-config in /etc/wireguard/<domain>.yaml
- sets up the automation requirements for building the local private netns, bird, and tunnel.

Create a host record to be imported on the site master.  The -a flag takes dns names and ip addresses, can be used multiple time.

        vpn-nodea$ wghost -t -a vpn-nodea.example.com [ -a 99.99.99.99 | -a 2001:01::0a ] mesh01.example.com
        Message to Home: cHVibGljX2tleTogTHBRQ3FFcy9nQlR3OHkyeTRiZUxYZEg0aC9QQUNTclQ2WWRYVUN0Z3dnND0KbWVzc2FnZTogISFiaW5hcnkgfAogIFRXVXllV28yUzBFd1pYVTVVRmN5Uld0Wk1IVTRiV1ZXWm01clZqSXZWbFZtYjJ0dksyWXdZamxYVEV0dVRraE9kek5xT1hKSWRXMW4KICBWbEV6YVU5QlJ6ZGlNa3d3VlVOQ1ZGVm9jd3BhVmtKd1ZIRkdiR1pJZUZNMlJYRkdZalJvUkhKcFRtcHpaekpaVjJ3clZWTjVZakJOCiAgZEdONVVWZzVTQzgxYkV4UVdqaEVUSFpuVkdaSmRrOVZNVXc0VUZKd1owcDRla1puYW1ObENtOXllV3R3TlhoMWVGVnJaWFJsYkVGNAogIFVEVmtSalpaTDI0M1QwbGtUbEEwYVU1RFZIVTBlRGx4TVRoc1QwNXFWRU4wVjNCcFVXRlBSMkpTVFhweVpUTXhWeko1YlROdlJuWjEKICBXVVlLTUdGR1pGTTVjbFZwTjBFeFNreFlSbEZLZFVaV0syRlNaMnA1YkVKTmJXdFhTM0Y1ZEVscFZVZzNXVGhKVGpoS2MwWXdZamhCCiAgVkV0NWExQktTRWhFVG5VclNqRmxNWFZMVVdsTGR3cGtPREZqV0ZSTGVXcGliSEJRVkRNMWNrZGFVRWhoYkhNNFJIaG1SRWQxVGt4bwogIGRuZFVUa1Z5TWtsVE1sRm1URE5CWm5OS2FuUklPVVIxYVZoemRXUjFObkpDUjNGak9XOHJkalp5Q21oVWNrWm1jV1JXTWs1VWFsY3cKICBVbUp0U0RNMllWSjZRakZaTDBFSwo=


Take the base64 hash, and import it on your site node. This payload is encrypted by the sites public key.

### Import the new node

        site-mgr$ wgsite -i <base64 payload here> <config.yaml>

Now, you can check the <config.yaml>, to see the changes.

Publish the changes, to cli or to route53:

        site-mgr$ wgpub -n <config.yaml>
        2024-03-24 07:45:41.313 | INFO     | wgmesh.pub:cli:75 - No DNS Commits will be made.
        |----| ## BEGIN HOST: vpn-nodea.example.com
        TXT:
        fe0a8e93-5681-4e2b-b251-dd9cb6da1e8b.mesh01.example.com

        DATA:
           (using AWS API to save changes...) 
        2024-03-24 07:45:42.399 | WARNING  | wgmesh.route53:save_txt_record:62 - Would have saved changes: fe0a8e93-5681-4e2b-b251-dd9cb6da1e8b.mesh01.example.conf // ['"0:KW/dMLW4mpyTx0MbRXun4rs7aNXVOOzmAcfJ/UwLaQqzeq5S5iLCajlpDPdje3QiEkPOXUcQEiit"', '"1:bLW6Q27VFjCsNfxzaiO1PtM0I+chHO7niNzZs0dptZ0Tp0Osobs4VTnVPnAtrNeGIqNVlkOO8SeQ"', '"2:74z63XQO3xmUC2FQarRz80VqyVnl6jg="'].

This payload into DNS now includes crucial information needed to run the wgdeploy script on the local node.

        vpn-nodea$ wgdeploy
