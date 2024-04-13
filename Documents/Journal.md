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

