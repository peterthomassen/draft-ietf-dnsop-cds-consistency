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
them from the child zone ("polling").
For CSYNC, this is described in [@!RFC7477] Section 3.1 which advocates
limiting polling queries to just one authoritative nameserver.
The corresponding Section 6.1 of [@!RFC7344] (CDS/CDNSKEY) contains no
such provision for how specifically polling of these records should be
done.

Implementations are thus likely to retrieve records from just one
authoritative server, typically by directing queries towards a trusted
validating resolver.
While that may be fine if all authoritative nameservers are controlled
by the same entity (typically the Child DNS Operator), it does pose a
problem as soon as multiple providers are involved.
(Note that it is generally impossible for the parent to determine
whether all authoritative nameservers are controlled by the same
entity.)

In such cases, CDS/CDNSKEY/CSYNC records retrieved "naively" from one
nameserver only may be entirely inconsistent with those of other
authoritative servers.
When no consistency check is done, each provider may unilaterally
trigger a roll of the DS or NS record set at the parent.

As a result, adverse consequences can arise in conjunction with the
multi-signer scenarios laid out in [@?RFC8901], both when deployed
temporarily (during a provider change) and permanently (in a
multi-homing setup).
For example, a single provider may (accidentally or maliciously) cause
another provider's trust anchors and/or nameservers to be removed from
the delegation.
Similar breakage can occur when the delegation has lame nameservers.
More detailed examples are given in (#scenarios).

A single provider should not be in the position to remove the other
providers' records from the delegation.
To address this issue, this document specifies that if polling is used,
parent-side entities MUST ensure that the updates indicated by
CDS/CDNSKEY and CSYNC record sets are consistent across all of the
child's authoritative nameservers, before taking any action based on
these records.

Readers are expected to be familiar with DNSSEC, including [@!RFC4033],
[@!RFC4034], [@!RFC4035], [@?RFC6781], [@!RFC7344], [@!RFC7477], and
[@?RFC8901].


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.

## Terminology

The terminology in this document is as defined in [@!RFC7344].


{#scenarios}
# Failure Scenarios

The following scenarios are examples of how things can go wrong when
consistency is not enforced by the parent during CDS/CDNSKEY/CSYNC
processing.
Other scenarios that cause similar (or perhaps even more) harm may
exist.

The common feature of these scenarios is that if one DNS provider steps
out of line and the parent is not careful, DNS resolution and/or
validation will break down, undermining the very guarantees of operator
independence that multi-homing configurations are expected to provide.

## Lame Delegations

A delegation may include a non-existent NS hostname, for example due to
a typo or when the nameserver's domain registration has expired.
(Re-)registering such a non-resolvable nameserver domain allows a third
party to run authoritative DNS service for all domains delegated to that
NS hostname, serving responses different from those in the legitimate
zonefile.

This strategy for hijacking (at least part of the) DNS traffic and
spoofing responses is not new, but surprisingly common [@?LAME1;@LAME2].
It is also known that DNSSEC reduces the impact of such an attack,
as validating resolvers will reject illegitimate responses due to lack
of signatures consistent with the delegation's DS records.

On the other hand, if the delegation is not protected by DNSSEC, the
rogue nameserver is not only able to serve unauthorized responses
without detection; it is even possible for the attacker to escalate the
nameserver takeover to a full domain takeover.

In particular, the rogue nameserver can publish CDS/CDNSKEY records.
If those are processed by the parent without ensuring consistency with
other authoritative nameservers, the delegation will be secured with
the attacker's DNSSEC keys.
As responses served by the remaining legitimate nameservers are not
signed with these keys, validating resolvers will start rejecting them.

Once DNSSEC is established, the attacker can use CSYNC to remove other
nameservers from the delegation at will (and potentially add new ones
under their control).
This enables the attacker to position themself as the only party
providing authoritiative DNS service for the victim domain,
significantly augmenting the attack's impact.


## Multi-Homing (Permanent Multi-Signer)

### DS Breakage

While performing a key rollover and adjusting the corresponding
CDS/CDNSKEY records, a provider could accidentally publish CDS/CDNSKEY
records that only include its own keys.

When the parent happens to retrieve the records from a nameserver
controlled by this provider, the other providers' DS records would be
removed from the delegation.
As a result, the zone is broken at least for some queries.

### NS Breakage

A similar scenario affects the CSYNC record, which is used to update the
delegation's NS record set at the parent.
The issue occurs, for example, when a provider accidentally includes
only their own set of hostnames in the local NS record set, or publishes
an otherwise flawed NS record set.

If the parent then observes a CSYNC signal and fetches the flawed NS
record set without ensuring consistency across nameservers, the
delegation may be updated in a way that breaks resolution or silently
reduces the multi-homing setup to a single-provider setup.

## Provider Change (Temporary Multi-Signer)

Transferring DNS service for a domain name from one (signing) DNS
provider to another, without going insecure, necessitates a brief period
during which the domain is operated in multi-signer mode:
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
retrieve the DNSKEY record set from the new provider, the old provider's
RRSIGs do no longer validate, causing responses to SERVFAIL.

However, an even worse consequence can occur when the parent performs
their next CDS/CDNSKEY scan:
It may then happen that the incorrect CDS/CDNSKEY record set is fetched
from the new provider and used to update the delegation's DS record set.
As a result, the old provider is prematureley removed from the domain's
DNSSEC chain of trust.
The new DS record set authenticates the new provider's DNSKEYs only, and
DNSSEC validation fails for all answers served by the old provider.


# Polling Requirements

This section defines consistency requirements for poll-based updates,
updating [@!RFC7344] Section 4.1 and [@!RFC7477] Sections 3.1 and 4.2.
Common ones are listed first, with type-specific criteria for polling
consistency described in each subsection.

In all cases, consistency is REQUIRED across received responses only.
Nameservers that appear to be unavailable SHOULD be disregarded as if
they were not part of the NS record set.

If an inconsistent polling state is encountered, the Parental Agent
MUST take no action.
Specifically, it MUST NOT delete or alter any existing RRset that would
have been deleted or altered, had the polling state been consistent.

To accommodate transient inconsistencies (e.g. replication delays), the
Parental Agent MAY retry the full process, repeating all queries.
A schedule with exponential back-off is RECOMMENDED (such as after 5,
10, 20, 40, ... minutes).


## CDS and CDNSKEY

To retrieve a Child's CDS/CDNSKEY RRset for DNSSEC delegation trust
maintenance, the Parental Agent, knowing both the Child zone name and
its NS hostnames, MUST ascertain that queries are made against all of
the nameservers listed in the Child's delegation from the Parent, and
ensure that each key referenced in any of the received answers is also
referenced in all other received responses.

In other words, CDS/CDNSKEY records at the Child zone apex MUST be
fetched directly from each of the authoritative servers as determined by
the delegation's NS record set, with DNSSEC validation enforced.
When a key is referenced in a CDS or CDNSKEY record set returned by
one nameserver, but is missing from a least one other nameserver's
answer, the CDS/CDNSKEY polling state MUST be considered inconsistent.


## CSYNC

A CSYNC-based update consists of (1) polling the CSYNC record to
determine which data records shall be synchronized from child to parent;
(2) querying for these data records (e.g. NS) and placing them in the
parent zone.
If the below conditions are not met during these steps, the CSYNC
polling state MUST be considered inconsistent.

When polling the CYSNC record set, the Parental Agent MUST ascertain
that queries are made against all of the nameservers listed in the
Child's delegation from the Parent, and ensure that the CSYNC record
sets are equal across all received responses.

When retrieving data record sets (e.g. NS), the Parental Agent MUST
ascertain that all queries are made against all of the nameservers
listed in the Child's delegation from the Parent, and ensure that the
record sets are all equal (including all empty).


# Security Considerations

The level of rigor mandated by this document is needed to prevent
publication of half-baked DS or delegation NS RRsets (authorized only
under an insufficient subset of authoritative nameservers), and ensures
that an operator in a multi-homing setup cannot unilaterally modify the
delegation (add or remove trust anchors or nameservers).
This applies both to intentional and unintentional multi-homing setups
(such as in the case of lame delegation hijacking).

As a consequence, the delegation's records can only be modified when
there is consensus across operators, which is expected to reflect the
domain owners intentions.
Both availability and integrity of the domain's DNS service benefit from
this policy.

In order to resolve situations in which consensus about child zone
contents cannot be reached (e.g. because one of the nameserver
providers is uncooperative), Parental Agents SHOULD continue to accept
DS and NS update requests from the domain owner via an authenticated
out-of-band channel (such as EPP [@!RFC5730]), irrespective of the rise
of automated delegation maintenance.


# Acknowledgments

Viktor Dukhovni


{backmatter}



<reference anchor="LAME1" target="http://dx.doi.org/10.1145/3419394.3423623">
  <front>
    <title>Unresolved Issues</title>
    <author fullname="Gautam Akiwate" surname="Akiwate">
      <organization>UC San Diego</organization>
    </author>
    <author fullname="Mattijs Jonker" surname="Jonker">
      <organization>University of Twente</organization>
    </author>
    <author fullname="Raffaele Sommese" surname="Sommese">
      <organization>University of Twente</organization>
    </author>
    <author fullname="Ian Foster" surname="Foster">
      <organization>DNS Coffee</organization>
    </author>
    <author fullname="Geoffrey M. Voelker" surname="Voelker">
      <organization>UC San Diego</organization>
    </author>
    <author fullname="Stefan Savage" surname="Savage">
      <organization>UC San Diego</organization>
    </author>
    <author fullname="KC Claffy" surname="Claffy">
      <organization>CAIDA/UC San Diego</organization>
    </author>
    <author>
      <organization>ACM</organization>
    </author>
    <date day="27" month="October" year="2020"/>
  </front>
  <refcontent>Proceedings of the ACM Internet Measurement Conference</refcontent>
  <seriesInfo name="DOI" value="10.1145/3419394.3423623"/>
</reference>
<reference anchor="LAME2" target="http://dx.doi.org/10.1145/3487552.3487816">
  <front>
    <title>Risky BIZness</title>
    <author fullname="Gautam Akiwate" surname="Akiwate">
      <organization>UC San Diego</organization>
    </author>
    <author fullname="Stefan Savage" surname="Savage">
      <organization>UC San Diego</organization>
    </author>
    <author fullname="Geoffrey M. Voelker" surname="Voelker">
      <organization>UC San Diego</organization>
    </author>
    <author fullname="K C Claffy" surname="Claffy">
      <organization>CAIDA/UC San Diego</organization>
    </author>
    <author>
      <organization>ACM</organization>
    </author>
    <date day="2" month="November" year="2021"/>
  </front>
  <refcontent>Proceedings of the 21st ACM Internet Measurement Conference</refcontent>
  <seriesInfo name="DOI" value="10.1145/3487552.3487816"/>
</reference>


# Change History (to be removed before publication)

* draft-ietf-dnsop-cds-consistency-00

* draft-thomassen-dnsop-cds-consistency-03

> Describe risk from lame delegations

> Acknowledgments

> Say what is being updated

> Editorial changes.

> Retry mechanism to resolve inconsistencies

* draft-thomassen-dnsop-cds-consistency-02

> Don't ignore DoE responses from individual nameservers (instead,
  require consistency across all responses received)

* draft-thomassen-dnsop-cds-consistency-01

> Allow for nameservers that don't respond or provide DoE (i.e. require
  consistency only among the non-empty answers received)

> Define similar requirements for CSYNC.

> Editorial changes.

* draft-thomassen-dnsop-cds-consistency-00

> Initial public draft.
