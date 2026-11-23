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

######## <BR>
<BR>
index="comp_*" (source_ip="10.139.52.11" OR source_hostname="tenable01") destination_domain="www.digicert.com"

index="comp_*"
(query="www.digicert.com")
(src_ip="10.139.52.11")


index=compc_* src_ip="10.139.52.11" ftnt_action=deny

1.	List all the Index names in your Splunk Instance<BR>
| eventcount summarize=false index=index_* | dedup index | fields index

2.	List all hosts that are logging to a particular index. In this example, we use company_cisco as the index.<BR>
index=company_cisco| table host | dedup host

3.	List all hosts that log to an index with eventcount per host. You can change the key word “host” to use “ip” too, based on your need.<BR>
index=company_cisco | stats count by host

4.	Sort by a field in the event ouput log<BR>
index=company_cisco | sort host

5.	Print the ouput event log in reverse order ( ascending order based on time )<BR>
index=company_cisco | reverse

6.	Print only the first 10 results from the eventlog<BR>
index=company_cisco | head 10

7.	Return only the last 10 results from the eventlog<BR>
index=company_cisco | tail 10

8.	 How to search a pattern on multiple splunk indexes in a single query ? <BR>Examples :<BR>
index=company_fortinet OR index=company_checkpoint | stats count by host

index=company_fortinet OR index=company_checkpoint | search error

9.	How to search a pattern and sort by count. This query will sort the results based on the output field “count”.<BR>
index=company_fortinet OR index=company_checkpoint | stats count by host | sort - count | head 15

index=company_fortinet OR index=company_checkpoint | top limit=15 host



#################
