## Wireguard Mesh Tool


This is a small project designed to experiment with distribution and maintenance of Wireguard Meshes for private networks using Protocol Routing


## Requirements

 - Fedora
 - Shorewall
 - Wireguard
 - Python


##  Getting Started

 - Create wgfrr.yaml from the wgfrr-example.yaml (example: create wgfrr.yaml)
 - Setup hostnames for the machines you want added.
 - Execute site publisher: `wgsite wgfrr.yaml`
 - Publish the DNS Information, or else, ensure that you have some other communication mechanism.
 - Install Wireguard tools on the local host `pip install wgmesh`
 - Deploy the mesh (run as root or sudo): `wghost <myhostname>`
 - import the host by copying the output into the site controlle


## Process Flow

  ![image](Documents/workflow.png)

 ## Ansible

  - local shorewall deployment
  - local frr deployment

 
 ## Changelog

  - 2020-12-04: Joshua Schmidlkofer - project setup