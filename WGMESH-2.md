## WGMESH 2.0

The 1.0 branch defined the problem.

The 2.0 branch should be involved with making the core code cleaner and more refined.

### Easy

* crypto operations should have their own module
* locus should be reported when we're doing stuff.
* trace should never reveal the private keys
* the cli needs to be simplified now that we know what we're using.
* dns cleanup dead/removed hosts needs to be a thing.
* wgsite should have a command to list/add/delete hosts
* wgsite --import should be an 'add' operation
* JSON should be used for all document exchange.  YAML is only for storing files.
* A means of rekeying the site, and the hosts should be addressed.
* Document the Communication workflow.
    * site init should be a series of questions.
        * wgsite --init
    * the init process should print instructions for the new user.
    * the host config should happen in 2 steps, using the same command.
    * the host setup process should print instructions for the new user.
        * wgsetup host <config>
        * wgsetup publish -> message

### Difficult

* dns should happen via extension points which can be used like interfaces.
* Eliminate shorewall and move to firewalld
* unit tests should be written for the crypto/communication process
    * generate a site
    * create two hosts
    * import keys
    * publish site config

The cli is inconsistent and all over the place.


## WGMESH 3.0

Implement the site-coordination API.  The logic needs to be worked out for this process, but
it is clear.

* Communication should happen via the wgmesh api
* Redundant hosts should be possible and normal
* some degree of firewall rules should be part of the host config
* interface-based routing protocol configuration

## Ideas without a home

* RAFT framework for connected nodes to pass configuration changes?
* Time-based check-in for node updates and upgrades

