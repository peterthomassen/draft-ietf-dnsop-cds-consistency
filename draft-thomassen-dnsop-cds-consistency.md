%%%
Title = "Consistency for CDS/CDNSKEY and CSYNC is Mandatory"
abbrev = "cds-consistency"
docname = "@DOCNAME@"
category = "std"
ipr = "trust200902"
updates = [7344, 7477]
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
organization = "Secure Systems Engineering, deSEC"
[author.address]
 email = "peter.thomassen@securesystems.de"
[author.address.postal]
 city = "Berlin"
 country = "Germany"
%%%


.# Abstract

Maintenance of DNS delegations requires occasional changes of the DS and
NS record sets on the parent side of the delegation.
[@!RFC7344] automates this for DS records by having the child publish
CDS and/or CDNSKEY records which hold the prospective DS parameters.
Similarly, CSYNC records indicate a desired update of the delegation's
NS records [@!RFC7477].
Parent-side entities (e.g. Registries, Registrars) typically discover
these records by periodically querying them from the child ("polling"),
before using them to update the delegation's parameters.

This document specifies that if polling is used, parent-side entities
MUST ensure that updates triggered via CDS/CDNSKEY and CSYNC records
are consistent across the child's authoritative nameservers, before
taking any action based on these records.

{mainmatter}

# Introduction

[@!RFC7344] automates DNSSEC delegation trust maintenance by having the
child publish CDS and/or CDNSKEY records which hold the prospective DS
parameters.
Similarly, [@!RFC7477] specifies CSYNC records indicating a desired
update of the delegation's NS records.
Parent-side entities (e.g. Registries, Registrars) can use these records
to update the delegation's DS and NS records.

A common method for discovering these signals is to periodically query
them from the child zone ("polling"), as described in Section 6.1 of
[@!RFC7344] (CDS/CDNSKEY) and Section 3.1 of [@!RFC7477] (CSYNC).

While [@!RFC7344] does specify acceptance rules (Section 4.1) for
CDS/CDNSKEY records that have been retrieved, it does not mention how
specifically the poll queries should be done.
For CSYNC, [@!RFC7477] leaves it up to the parent to decide from how
many nameservers the records are retrieved (Section 4.2).
A naive implementation would thus be likely to retrieve records from
just one authoritative server, possibly by directing queries towards a
trusted validating resolver.

This may be fine if all authoritative nameservers are controlled by the
same entity (typically the DNS operator).
However, it poses a problem in conjunction with the multi-signer
scenarios laid out in [@!RFC8901], both when deployed temporarily
(during a provider change) or permanently (in a multi-homing setup).

CDS/CDNSKEY/CSYNC records retrieved "naively" from one nameserver only
may be entirely inconsistent with those of other authoritative servers.
When several providers are configured and no consistency check is done,
a single provider could (accidentally or maliciously) roll the DS or NS
record set at the parent and, for example, remove the other provider's
trust anchors and/or nameservers from the delegation.
More detailed examples are given in (#scenarios).

Whether in a permanent multi-homing setup or during provider change:
A single provider should not be in the position to remove the other
providers' records from the delegation.

To address this issue, this document specifies that if polling is used,
parent-side entities MUST ensure that the updates indicated by
CDS/CDNSKEY and CSYNC record sets are consistent across all of the
child's authoritative nameservers, before taking any action based on
these records.

Readers are expected to be familiar with DNSSEC, including [@!RFC4033],
[@!RFC4034], [@!RFC4035], [@!RFC6781], [@!RFC7344], [@!RFC7477], and
[@!RFC8901].


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.


{#scenarios}
# Failure Scenarios

The following scenarios are examples of how things can go wrong when
consistency is not enforced by the parent during CDS/CDNSKEY/CSYNC
processing.
Other scenarios that cause similar (or perhaps even more) harm may
exist.

The common feature of these scenarios is that if one DNS provider makes
a mistake and the parent is not careful, DNS resolution and/or
validation will break down, undermining the very guarantees of operator
independence that DNSSEC multi-signer models are intended to provide.

## Multi-Homing (Permanent Multi-Signer)

### DS Breakage

While performing a key rollover and adjusting the corresponding
CDS/CDNSKEY records, a provider could accidentally publish CDS/CDNSKEY
records that only include its own keys.

When the parent happens to retrieve the records from a nameserver
controlled by this provider, the other providers' DS records would be
removed from the parent.
As a result, the zone is broken at least for some queries.

### NS Breakage

A similar scenario affects the CSYNC record, which is used to update the
delegation's NS record set at the parent.
The issue occurs, for example, when a provider accidentally includes
only their own set of hostnames in the local NS record set, or publishes
an otherwise flawed NS record set.

If the parent then observes a CSYNC signal and fetches the flawed NS
record set without ensuring consistency across nameservers, the
delegation may be updated so that resolution is broken, or the
multi-homing setup is silently reduced to a single-provider setup.

## Provider Change (Temporary Multi-Signer)

Transferring a domain from one (signing) DNS provider to another,
without going insecure, necessitates a brief period during which the
domain is operated in multi-signer mode:
First, the providers include each other's signing keys as DNSKEY and
CDS/CDNSKEY records in their copy of the zone.
Once the parent detects the updated CDS/CDNSKEY record set at the old
provider, the delegation's DS record set is updated.
Then, after waiting for cache expiration, the new provider's NS
hostnames can be added to the zone's NS record set, so that queries
start balancing across both providers.
(To conclude the hand-over, the old provider is removed by inverting
these steps with swapped roles.)

The multi-signer phase of this process breaks when the new provider
fails to include the old provider's keys in the DNSKEY and CDS/CDNSKEY
record sets.
One obvious consequence of that is that whenever the resolver happens to
retrieve the DNKSEY record set from the new provider, the old provider's
RRSIGs do no longer validate, causing to SERVFAIL responses.

However, an even worse consequence can occur when the parent performs
their next CDS/CDNSKEY scan:
It may then happen that the incorrect CDS/CDNSKEY record set is fetched
from the new provider and used to update the delegation's DS record set.
As a result, the old provider is prematureley removed from the domain's
DNSSEC chain of trust.
The new DS record set authenticates the new provider's DNSKEYs only, and
DNSSEC validation fails for all answers served by the old provider.


# Performing a Poll-based CDS or CDNSKEY Update

The terminology in this section is as defined in [@!RFC7344].

To retrieve a Child's CDS/CDNSKEY RRset for DNSSEC delegation trust
maintenance, the Parental Agent, knowing both the Child zone name and
its NS hostnames, MUST ascertain that queries are made against all of
the nameservers listed in the Child's delegation from the Parent, and
ensure that each key referenced in any of the non-empty answers is also
referenced in all other non-empty answers.

In other words, CDS/CDNSKEY records at the Child zone apex MUST be
fetched directly from each of the authoritative servers as determined by
the delegation's NS record set, with DNSSEC validation enforced.
When a key is referenced in a CDS or CDNSKEY record set returned by
one nameserver, but is missing from a least one other nameserver's
non-empty answer, the CDS/CDNSKEY state MUST be considered inconsistent.

Consistency is only REQUIRED across non-empty answers: Nameservers that
provide valid proof of non-existence or do not respond SHOULD be
disregarded.

If an inconsistent CDS/CDNSKEY state is encountered, the Parental Agent
MUST take no action.
Specifically, it MUST NOT delete or alter the existing DS RRset.


# Performing a Poll-based CSYNC Update

A CSYNC-based update consists of (1) polling the CSYNC record to
determine which data records shall be synchronized from child to parent;
(2) querying for these data records (e.g. NS) and placing them in the
parent zone.
Both steps are described separately below.

If an inconsistent CSYNC state is encountered in the process, the
Parental Agent MUST take no action.
Specifically, it MUST NOT delete or alter any existing NS or other data
RRset.

## Querying for CSYNC

When retrieving CYSNC record sets, the Parental Agent MUST ascertain
that queries are made against all of the nameservers listed in the
Child's delegation from the Parent, and ensure that the CSYNC record
sets are equal across all non-empty answers.
Otherwise, the CSYNC state MUST be considered inconsistent.

For CSYNC queries, consistency is only REQUIRED across non-empty
answers: Nameservers that provide valid proof of non-existence or do not
respond SHOULD be disregarded.
(This is like for CDS/CDNSKEY queries above.)

## Querying for Data Records (e.g. NS)

When retrieving data records (e.g. NS), the Parental Agent MUST
ascertain that all queries are made against all of the nameservers
listed in the Child's delegation from the Parent, and ensure that all
answers received are equal.
Otherwise, the CSYNC state MUST be considered inconsistent.

Unlike for CSYNC queries, answers MUST be all non-empty and equal, or
all empty.
Unresponsive nameservers SHOULD be disregarded.
If both an empty and a non-empty answer is received for a data record
query, the state MUST be considered inconsistent.

# Security Considerations

The level of rigor mandated by this document is needed to prevent
publication of a half-baked DS or NS RRsets (authorized only under an
insufficient subset of authoritative nameservers).
This ensures, for example, that an operator in a multi-homed setup
cannot unilaterally remove another operator's trust anchor or
nameservers from the delegation.

As a consequence, the delegation's records can only be modified when
there is consensus across operators.


{backmatter}


# Change History (to be removed before publication)

* draft-thomassen-dnsop-cds-consistency-01

> Allow for nameservers that don't respond or provide DoE (i.e. require
  consistency only among the non-empty answers received)

> Define similar requirements for CSYNC.

> Editorial changes.

* draft-thomassen-dnsop-cds-consistency-00

> Initial public draft.
