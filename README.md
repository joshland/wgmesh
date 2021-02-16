## Wireguard Mesh Tool


This is a small project designed to experiment with distribution and maintenance of Wireguard Meshes for private networks using Protocol Routing.

Of necessity, the Routing Daemons are running against the wireguard interfaces.

If there are local Routing Requirements, they are beyond the scope of this mesh development.  This is intended to produce a routing mesh - care and feeding of the mesh is your responsibility.


## Requirements

 - [Fedora](https://getfedora.org/en/server/#:~:text=Fedora%20Server%20is%20a%20short,in%20the%20open%20source%20community.) _prolly any modern linux will work_
 - [Wireguard](https://www.wireguard.com/) _included with Fedora (wireguard-tools)_
 - [Python](https://www.python.org/) _included with almost all modern linux_
 - [BIRD](https://bird.network.cz/) _modular protocol routing daemon_
 - [GIT](https://git-scm.com/) _Source Control_

## TODO

 - Local Site-specific configurations integration?
 - systemctl @ service - bird for the netns 'bird@private'.
 - startup script should prolly be written in python.
 - Non-dns method of transmitting deploy_messages.

##  Getting Started

Example config: `wgfrr.yaml`
Example Domain: `mesh.example.com`

 ** Site Config **
 - Copy wgfrr-example.yaml to `wgfrr.yaml`
 - Edit the file and set the primitives.
 - Execute site publisher: `wgsite wgfrr.yaml`
 - Publish the DNS Information. (TXT record 'mesh.example.com')

 ** Endpoint Config **
 - Connect to mesh endpoints, setup python virtualenv.
 - Install Wireguard tools on the local host `pip install wgmesh`
 - Setup host registration the mesh (run as root or sudo): `wgconfig -i ens4 -o veth0 -T ens3 -I 172.16.143.22/24 mesh.erickson.is`
 - Configure the local host `wgconfig -i enp0s1 -t enp0s2 -T veth0 -I 172.16.140.21/24`

 ** Site Config **
 - Import the host by copying the output into the site controller. `wgsite -i <hash> wgfrr.yaml`
 - Once host(s) are ready, publish Host-base DNS records: `wgpub wgfrr.yaml`
 - Publish output to the `[uuid].wgfrr.example.com` TXT records.

 ** Endpoint Config **
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