#!/bin/bash

#Run from within the 

watch -n1 "birdc -s /var/run/bird-private.sock show prot;echo '';birdc -s /var/run/bird-private.sock show bfd session;echo '';birdc -s /var/run/bird-private.sock show route count"
