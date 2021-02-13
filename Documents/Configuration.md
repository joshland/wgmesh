
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
