# IOC-Verifier
Powershell based script to Verify malware Indicators of Compromise (IOC Hashes, domains, IPs) against databases such as VirusTotal and Kaspersky

Register and following sites and get API keys. Put these keys in the mentioned spaces within the single quotes in the script. VirusTotal support multiple API keys to bypass daily/monthly limits.
	https://www.virustotal.com/
	https://opentip.kaspersky.com/
	https://www.abuseipdb.com/


Usage:
	1. Add the list of IOC into ioc.txt. Supports hashes, domains and IPs. One per line.
	2. Run script.
	3. Report will be available in the reports folder.
