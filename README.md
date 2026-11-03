# Splunk
This is a quick dump to get started with Splunk and getting some data during an incident response or just to browse Splunk for valuable data. More to come for sure....

index=* | lookup dnslookup clienthost as hostname

index=* | lookup dnslookup clientip as ipaddress

sourcetype="WinEventLog" EventCode=4688 | stats count by New_Process_Name, Process_Command_Line

index="*" sourcetype="stream:http" topology4.dyndns.atlas.ripe.net

State != Closed AND assignment_group Name contains TSG-NTT-L4 AND Risk group not in (P4, P5, P7) AND Location = PTC Data Center .or. Location = WTC Data Center .or.
Location is empty AND Source = qualys


#############
index=* source="*" EventCode=4720 OR (EventCode=4732 Administrators)

index=* source="*" (EventCode=5140 OR EventCode=560) (C$ OR ADMIN$)

Detect Network Crawling:
index=* source="*" EventCode=4769


AD - sensitive group change:
index=* sourcetype=* AND EventCode=4728 OR EventCode=4729 OR EventCode=4732 OR EventCode=4733 OR EventCode=4756 OR EventCode=4757

Account lockouts:

#########
look for Windows updates with hostname:
The following splunk query will return results on any Windows Updates (Patches) that have been applied by searching for the KB value associated with the EventID.

sourcetype=WinEventLog:System EventCode=19 | eval Date=strftime(_time, "%Y/%m/%d")| rex "\WKB(?<KB>.\d+)\W" |stats count by Date, host, KB

############
search code 4625 for 'an account failed to log on'
index=* (sprasobh or oporada or mgergel) and 4625 source="WinEventLog:ForwardedEvents"

########
