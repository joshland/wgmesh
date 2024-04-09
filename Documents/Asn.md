## ASN Trouble

ASN assignment is automated and problematic - you can always manually assign them, but
the automated assignment is more advantageous.  Since I don't know how other people will
be implementing this, I have some degree of discomfort with the entire notion.

The Fire-and-forget from the initial wgmesh release has been unpleasant to work around
in some installations.

Auto-checkout is the best approach for adding new hosts, but a host might supply it's 
own ASN.  The numbers are arbitrary and there is no need treat them any different from all
other forms of addressing.

### Principles

- Default pool

- No errors if you don't specify one

- Absolutely required for the nodes.

- Separate ASN checks for sanities sake.


