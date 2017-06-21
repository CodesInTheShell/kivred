# kivred
Cyber threat intelligence software serves as a TAXII client to fetch STIX data from a TAXII server.


============================================================================================================
This software serves as a taxii client that can be use to fetch stix data from a taxii server.

TAXII - Trusted Automated eXchange of Indicator Information. A free and open transport mechanism that standardizes
the automated exchange of cyber threat information.

STIX - Structured Threat Information Expression. is a language for describing cyber threat information
in a standardized and structured manner to enable the exchange of cyber threat intelligence (CTI).

Indicator – contains a pattern that can be used to detect suspicious or malicious cyber activity.

Observed Data – conveys information observed on a system or network (e.g., an IP address).

TTPs - Tactics, Techniques, and Procedures. (e.i., Malware, Attack Pattern)

References and more information can be found on the following:
https://www.oasis-open.org/
https://oasis-open.github.io/cti-documentation/

===========================================================================================================
This product is tested to fetch data from hailataxii.

Discovery URL: http://hailataxii.com/taxii-discovery-service

Username: guest
Password: guest

Available feeds:
    guest.Abuse_ch
    guest.CyberCrime_Tracker
    guest.EmergingThreats_rules
    guest.Lehigh_edu
    guest.MalwareDomainList_Hostlist
    guest.blutmagie_de_torExits
    guest.dataForLast_7daysOnly
    guest.dshield_BlockList
    guest.phishtank_com

More information can be found in there website.

NOTES:

When receiving a chunk size error on your request, maybe it is due to a large volume of data.
You may need to shorten the from and to stamp. A length of one day can give you a huge amount of result.

When nothing is shown on Indicators, Observables and TTPs, you may want to check the raw output for issue.



