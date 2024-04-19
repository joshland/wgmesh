## 2024-04-09 21:15

ASN automation logic removed.

ASN loading from site file still broken. Conflicting details on load, either incomplete setup or a 
function is resetting the asn_used range.

- unit tests passing
- addhost -> does not set asn
- --asnfix working, but subsequent operations are breaking asn_used

## 2024-04-10 22:00

ASN logic is gone, but the object<->data model was broken too.  This has been rewritten.

Site
 -> Sitecfg
 -> *Hosts

This relationship is still a little tight and inflexible, but it was done to fix the irreconcilable
differences without refactoring everything.  The current practice of storing and loading, basic transforms,
basic configuration changes, and parameter updates is working.

The endpoints have been a little neglected. ASN adjustment needs to bepossible on the node, it should override the
Site, and the updates will follow.  There is an outstanding question about the octect management. Octet mapping
is simpler if you let the wgmesh logic handle it entirely.

No work has been started on local deployment work.  This remains entirely unhandled. The central document process
is what I am concerned with accurately handling. The Site config, host config, endpoint config, Site Records, 
Host Records, and next Deploy Records should all be modeled and defined properly.

Once the definitions and basic RPC is accomplished, the API contract will be effectively written, and then
API server work will be possible.

My goal is to remain above a score of 7 overall on linting.  All of the library modules are 8+ OOTB, but the
CLI sections are low-scoring. Some of this can be addressed, but without disabling warnings, there are some
stock lints which will trigger.

I need to calculate the pytest code coverage.  I think that 40% is the rough ideal. Unittests didn't break
from the refactoring, the new ABI changes had to be incorporate, but the ridiculous ASN assignment
problem is now entirely gone.  

One new test is due: ASN exhaustion test.  We should not fail on ASN exhaustion, but we _must_ fail 
on ASN deployment, if we don't have an ASN. It is highly probable that some installations will be entirely
automate, while others are hand-chosen, like IP addresses.

The wgsite may need to be able to _define_ hosts, but, since that breaks our communication model I 
think that I will leave that an an exercise to the end user.

Host -> Uuid -> Key(s) -> Registration -> Adoption -> Deployment

that is the entire working pipeline for today

## 2024-04-11 18:18

Lint cleanups after refactoring, lots of variable name adjustments to recognize the new site structure.

Goal: return basic transforms which broke to service

Bug: Outstading problems with refactoring the ASN and Octets. Host import broken. (should this be renamed to 
adopt?)


## 2024-04-12 22:26

Updates to several core functions, working on deployment records for the nodes.  Working with wgsite.publish.
Down in the bottom, we have severl bugs, including the old/ugly site_report, which needs to be fixed for the
changes in the ABI.

## 2024-04-13 12:30

Merged ASN disablement into wgmesh-2 branch.  Continuing with production of the publishing setup. I'm concerned
about the deletion process, auditting the DNS records, and managing old/stale/dead records. Eventually the API
will eliminte this, but the DNS method is going to be around for a while since it's in use.

I think that a general DNS/storage abstraction needs to be written. We need the ability to find records, validate
records, and store versions of the encrypted records locally. The DNS will probably need to be sync'd with a sqlite
database or something similar.

THen, we can have Record Creation -> Record Sync -> Record Verification -> Record Audits.

## 2024-04-17 21:34

Implemented store_dns.  It is a simpler API, the data is simpler, and it is fast and easy.  It needs a little
detail written on how to use it.  However, the essentials are clear.

DNSDataClass(zone, sitename, aws_access, aws_secret)

The classmethod openZone allows immediate connection, otherwise, it connects on the first operation. I think
that I might want to jsue use the EncryptedAwsSecret class for this, but instead, I am just mapping details
around.

The key opportunities is the fact that create_text_record returns an rrset, and the save() operation only
returns the AWS JSON Body.

It seemlessly handles and enumerates all the records in a site, and it allows easy access, listing, and removal.

Ultimately, there are two mthods, 'write_site', and "write_host".  These make updating the DNS details
trivial, and it creates the opportunity for further details.  I think that I will extend the classes just
a little bit - the key that I want is to retain a local records of the unencrypted site data so that i 
don't endlessly update encrypted messages.

## 2024-04-18

Import/Export problems: host import doesn't render the public key, and it's not getting imported

    published host: Munch({'uuid': 'aee8a79f-c608-4fe9-8484-cdef6911366f', 'hostname': 'AtomBattler.ashbyte.com', 'asn': -1, 'octet': 2, 'local_ipv4': ['4.2.2.2/32', '8.8.8.8/32'], 'local_ipv6': ['fd86:ea04:1116::1/128'], 'public_key': '', 'local_networks': '', 'public_key_file': 'dev/example_endpoint_pub', 'private_key_file': 'dev/example_endpoint_priv'})

The endpoint either isn't loading the key, or else isn't exporting it - since we have the message,
and it should be signed, we should have confidence that this is actually present. 

 - Examine the key, and then re-reun the tests.

