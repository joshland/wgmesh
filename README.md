## Wireguard Mesh Tool


This is a small project designed to experiment with distribution and maintenance of Wireguard Meshes for private networks using Protocol Routing.

Of necessity, the Routing Daemons are running against the wireguard interfaces.

If there are local Routing Requirements, they are beyond the scope of this mesh development.  This is intended to produce a routing mesh - care and feeding of the mesh is your responsibility.


## Requirements

 - Fedora
 - Wireguard
 - Python
 - FRR w/ BGP

## TODO

 - Router IDs
 - BGP ASN configuration
 - Local Site-specific configurations integration?

# Local Config

  - Create private namespace
  - Create veth pub/priv, local addr 169.254.[port].1/24 => [port].2/24
  - enable ipv4/ipv6 routing / public and private
  - private / 127.0.0.1
  - private / inner interface
  - shorewall port forwarding
  - shorewall NAT for 168.254.[port] to internet.
  - schedule startup.
  - bird6/Point-to-Point eBGP
  - bird/bird6 internal process for local network
  - Internal protocol routes access - eBGP is graceful, OSPF is disruptive. 😢

##  Getting Started

Example config: `wgfrr.yaml`
Example Domain: `mesh.example.com`

 - Copy wgfrr-example.yaml to `wgfrr.yaml`
 - Edit the file and set the primitives.
 - Execute site publisher: `wgsite wgfrr.yaml`
 - Publish the DNS Information. (TXT record 'mesh.example.com')
 - Connect to mesh endpoints, setup python virtualenv.
 - Install Wireguard tools on the local host `pip install wgmesh`
 - Deploy the mesh (run as root or sudo): `wghost mesh.example.com`
 - Import the host by copying the output into the site controller. `wgsite -i <hash> wgfrr.yaml`
 - Once host(s) are ready, publish Host-base DNS records: `wgpub wgfrr.yaml`
 - Publish output to the `[uuid].wgfrr.example.com` TXT records.
 - Deploy on the local hosts: `wgdeploy mesh.example.com`

 Publish and deploy processes can be automated.

## Warnings:

 `wghost` setup, and `wgsite -i` must be a human-approved process, because this adds nodes to the mesh.

## Process Flow

  ![image](Documents/workflow.png)

 ## Ansible

  - local shorewall deployment
  - local frr deployment

 
 ## Changelog

  - 2020-12-04: Joshua Schmidlkofer - project setup