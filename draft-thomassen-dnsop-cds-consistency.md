%%%
Title = "Ensuring CDS/CDNSKEY Consistency is Mandatory"
abbrev = "cds-consistency"
docname = "@DOCNAME@"
category = "std"
ipr = "trust200902"
updates = [7344]
area = "Internet"
workgroup = "DNSOP Working Group"
date = @TODAY@

[seriesInfo]
name = "Internet-Draft"
value = "@DOCNAME@"
stream = "IETF"
status = "standard"

[[author]]
initials = "P."
surname = "Thomassen"
fullname = "Peter Thomassen"
organization = "deSEC, Secure Systems Engineering"
[author.address]
 email = "peter@desec.io"
[author.address.postal]
 city = "Berlin"
 country = "Germany"
%%%


.# Abstract

For maintaining DNSSEC Delegation Trust, DS records have to be kept up
to date.
[@!RFC7344] automates this by having the child publish CDS and/or
CDNSKEY records which hold the prospective DS parameters.
Parent-side entities (e.g. Registries, Registrars) can use these records
to update the delegation's DS records.
A common method for detecting changes in CDS/CDNSKEY record sets is to
query them periodically from the child zone ("polling"), as described in
Section 6.1 of [@!RFC7344].

This document specifies that if polling is used, parent-side entities
MUST ensure that CDS/CDNSKEY record sets are equivalent across all of
the child's authoritative nameservers, before taking any action based on
these records.

{mainmatter}

# Introduction

[@!RFC7344] automates DNSSEC delegation trust maintenance by having the
child publish CDS and/or CDNSKEY records which hold the prospective DS
parameters.
Parent-side entities (e.g. Registries, Registrars) can use these records
to update the delegation's DS records.
A common method for detecting changes in CDS/CDNSKEY record sets is to
query them periodically from the child zone ("polling"), as described in
Section 6.1 of [@!RFC7344].

While [@!RFC7344] does specify acceptance rules (Section 4.1 ) for
CDS/CDNSKEY records that have been retrieved, it does not mention how
specifically the poll queries should be done.
A naive implementation would thus be likely to simply query CDS or
CDNSKEY records through a trusted validating resolver, and use the
validated answer.

This may be fine if all authoritative nameservers are controlled by the
same entity (= DNS operator).
However, it poses a problem in conjunction with multi-signer setups
([@!RFC8901]):
When the CDS/CDNSKEY are retrieved "normally" using a validating
resolver, chances are that records are retrieved from one nameserver
only, without checking for consistency across other NS hostnames.

In a multi-signer setup, this means that a single provider could
(accidentally or maliciously) roll the DS record set at the parent.
For example, a provider could be performing a key rollover and then
accidentally publish CDS/CDNSKEY records for its own keys.
As a result, when the parent happens to retrieve the records from a
nameserver controlled by this provider, the other providers' DS records
would be removed from the parent, breaking the zone for some or all
queries.

A single provider should not be in the position to remove the other
providers' trust anchors.
To address this issue, this document specifies that if polling is used,
parent-side entities MUST ensure that CDS/CDNSKEY record sets are
equivalent across all of the child's authoritative nameservers, before
taking any action based on these records.

Readers are expected to be familiar with DNSSEC, including [@!RFC4033],
[@!RFC4034], [@!RFC4035], [@!RFC6781], [@!RFC7344], and [@!RFC8901].


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.


# Polling a CDS or CDNSKEY Record Set

The terminology in this section is as defined in [@!RFC7344].

To retrieve a Child's CDS/CDNSKEY RRset for DNSSEC delegation trust
maintenance, the Parental Agent, knowing both the Child zone name and
its NS hostnames, MUST ascertain that queries are made against all of
the nameservers listed in the Child's delegation from the Parent, and
ensure that the set of referenced keys is equal.

In other words, CDS/CDNSKEY records at the Child zone apex MUST be
queried directly from each of the authoritative servers as determined by
the delegation's NS record set, with DNSSEC validation enforced.
When a key is referenced in the CDS or CDNSKEY record set returned by
one nameserver, but not referenced in the corresponding answers of all
of the other nameservers, the CDS/CDNSKEY state MUST be considered
inconsistent.

If an inconsistent CDS/CDNSKEY state is encountered, the Parental Agent
MUST take no action.
Specifically, it MUST NOT delete or alter the existing DS RRset.


# Security Considerations

The level of rigor mandated by this document is needed to prevent
publication of a half-baked DS RRset (authorized only under a subset
of NS hostnames).
This ensures, for example, that an operator in a multi-homed setup
cannot unilaterally remove another operator's trust anchor from the
delegation's DS records.

As a consequence, DS records can only be modified when there is
consensus across all operators.


{backmatter}


# Change History (to be removed before publication)

* draft-thomassen-dnsop-cds-consistency-00

> Initial public draft.
