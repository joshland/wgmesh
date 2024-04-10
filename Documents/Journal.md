## 2024-04-09 21:15

ASN automation logic removed.

ASN loading from site file still broken. Conflicting details on load, either incomplete setup or a 
function is resetting the asn_used range.

- unit tests passing
- addhost -> does not set asn
- --asnfix working, but subsequent operations are breaking asn_used


