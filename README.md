<h1 align="center">VERF</h1>
<h3 align="center">Powershell based IOC Verifier</h3>

## About
Powershell based script to call upon APIs of Malware databases to verify the nature of given Indicators of Compromise(IOCs). Supported IOCs(See: [Additional Info](#iocs--filtering)):
- Hashes 
- URLs
- Domains 
- IPs

Following are the currently supported services.
- [VirusTotal](https://www.virustotal.com/)
- [Kaspersky](https://opentip.kaspersky.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Intezer](https://analyze.intezer.com/)

Current Features:
- Multiple API Key support ([?](#api-rate-limiting))
- IOC Filtering ([?](#iocs--filtering))
- Caching ([?](#temporary-caching))
</br>

## Getting Started:
1. Move the powershell script `VERF-IOC-Verifier.ps1` to a directory of your choice. Additional files and folders will be created during runtime, so its recommended to keep the file in a seperate folder.
2. Put the IOCs in `ioc.txt` (Default).
3. Register on any/all services mentioned above and aqcuire API Keys.
4. Put the APIs in the script. (See: [API Keys](#api-keys))
5. Run the script, Results will be saved as a csv file under `Reports` folder.
</br>

## Configurable Settings
1. Defines the path/name for the file containing the IOC list.
```pwsh
$ioc_file = '.\ioc.txt'
```
2. Defines the path/name for the Temporary cache file. (See: [Temporary Caching](#additional-info))
```pwsh
$temp_cache_file = '.\VERF_Temp_Cache'
```
3. Query the selected platform only, see code for supported values.
```pwsh
$debug_platform = 0
```
4. Max number of comments to be extracted from AbuseIPDB results for the final report.
```pwsh
$abuseipdb_max_comments = 8
```
5. Enable/Disable temporary caching of IOCs.
```pwsh
$temp_cache_check = $true
```
6. Enable/Disable request rate limiting for services with rate limits. (See: [Additional Info](#additional-info))
```pwsh
$api_rate_limit = $true
```
7. VirusTotal wait time(seconds) for rate limiting.
```pwsh
$virustotal_timeout = 17
```
8. Words on this list will be removed from each line. (See: [IOC Filtering](#ioc-filtering))
```pwsh
$filter_words = @('www.', '[', ']', 'http://', 'https://', 'hxxp://', 'hxxps://')
```
</br>

## Additional Info
### API Keys
These can be aqcuired through registering in supported services. Following services are currently supported,
- [VirusTotal](https://www.virustotal.com/)
- [Kaspersky](https://opentip.kaspersky.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Intezer](https://analyze.intezer.com/)

Once you have the key paste it into the corresponding service's array. Multiple keys per platform is supported. ie:
```pwsh
$virustotal_keys = @(
    'xxxxxxxxxxxxxxxxxx', #Replace these with keys, multiple entries are comma ',' seperated.
    'xxxxxxxxxxxxxxxxxx'
)
```

### API Rate limiting
Some services has a limit on how man requests can be performed at a given time with public/free keys. This can be bypassed with the multiple key support feature. But if you dont want to be bothered with creating multiple accounts and don't mind waiting the extra time the rate limiting feature can be enabled. This is Enabled by default. See: [Configurable Settings:6](#configurable-settings)

Currently supported service limitation on free keys:
- VirusTotal: 4/minute, 500/day
- Kaspersky: 200/day
- AbuseIPDB: 1000/day
- Intezer: N/A(?)

### Temporary Caching
When caching is enabled, a file `VERF_Temp_Cache`(Default) will be created in the same directory as the script. Every unique IOCs will be saved. This is mainly to avoid duplicate values specially from URLs since some could resolve to same Domain/IP. 

This can also be used to resume checks if the script was stopped mid way, since only at the end is this file automatically delete. This is Enabled by default. See: [Configurable Settings:5](#configurable-settings)

### IOCs & Filtering
Currently only one IOC will be looked into per line, so make sure there's only one per line. The filtering process will first remove all the given words and characters before using the Regex to isolate the IOC, this will ease the burden on regex which could lead to unexpected results. To add/remove words to filter out See : [Configurable Settings:8](#configurable-settings)

Following IOCs are supported:
- Hashes (MD5, SHA1, SHA256) : 
- URLs (Will be filtered for the Domain/IP)
- (Sub)Domains 
- IPs (v4)

IOCs supported by services:
- VirusTotal: All
- Kaspersky: All
- AbuseIPDB: IPs only
- Interzer: Hashes Only
</br>

## Contribution
The code is far from efficient/clean/bug-free. Any improvements and feedbacks are welcome. Contact me @ ddulshan100@gmail.com