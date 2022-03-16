<#
    
	VERF - IOC Verifier
    Version : 1.0
    Creator : Dunura Dulshan | https://github.com/ddulshan
    Description : Script to call Malware databases such as VirusTotal, Kaspersky and AbuseIPDB API for information on given query
   
#>

# API URLs
$virustotal_url = "https://www.virustotal.com/api/v3/"   #ip_addresses, domains, hashes
$kaspersky_url = "https://opentip.kaspersky.com/api/v1/search/" #hash?request=<hash>
$abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"

# Platform Dictionary
$platforms = @{
    1 = 'VirusTotal'
    2 = 'Kaspersky'
    4 = 'AbuseIPDB'
}

# URL Dictionaries
$virustotal_url_type = @{
    'hash' = 'files/'
    'ip' = 'ip_addresses/'
    'domain' = 'domains/'
}
$kaspersky_url_type = @{
    'hash' = 'hash'
    'ip' = 'ip'
    'domain' = 'domain'
}

# Words and characters to remove/split in filtering process
$filter_words = @('www.', '[', ']', 'http://', 'https://', 'hxxp://', 'hxxps://')
$split_chars = @('/', ':')

# IOC Information class
class query_class {
    $query = ''
    $file_name ='-'
    $rating = '-'
    $comments = '-'
    $reports = '-'
    $detection_type = [System.Collections.ArrayList]::new()
    $first_seen = '-'
    $last_seen = '-'
    $link = '-'
    $ioc_type = ''
    $hash_type = ''
    $platform = '-'
    $md5 = '-'
    $sha1 = '-'
    $sha256 = '-'

    query_class () {
        $this.detection_type.Add('-')
    }
}

# Other Settings
$ioc_file = '.\ioc.txt'
$temp_cache_file = '.\temp_cache'
$debug_platform = 0 #0-debuf off, 1-VT, 2-Kasper, 4-AbuseIPDB
$abuseipdb_max_comments = 8
$temp_cache_check = $true
$global:virustotal_current_key = 0
$global:kaspersky_current_key = 0
$global:absueipdb_current_key = 0
$global:current_filename = ''
#$virustotal_timeout = 17 #For VirusTotal query limit. 4/minute, 500/day

<# API KEYS
	Multiple keys supported. Comma ',' seperated. ie:
		
		$virustotal_keys = @(
			'XXXXX',
			'XXXXX',
			'XXXXX'
		)
#>
$virustotal_keys = @(
    '!!!!!!ADD VIRUSTOTAL API KEYS HERE!!!!!'
)
$kaspersky_keys = @(
    '!!!!!!ADD Kaspersky API KEYS HERE!!!!!' 
)
$abuseipdb_keys = @(
    '!!!!!!ADD AbuseIPDB API KEYS HERE!!!!!'
)

# Request Headers
$virustotal_headers = @{
    'x-apikey' = $virustotal_keys[$virustotal_current_key]
}
$kaspersky_headers = @{
    'x-api-key' = $kaspersky_keys[$kaspersky_current_key]
}
$abuseipdb_headers = @{
    'Key' = $abuseipdb_keys[$absueipdb_current_key]
}

# Request Bodies
$abuseipdb_body = @{
    'ipAddress' = ''
    'maxAgeInDays' = '30'
    'verbose' = ''
}
$kaspersky_body = @{
    'request' = ""
}

# Regex
[regex]$regex_ipv4 = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
[regex]$regex_sha1 = '\b([a-f0-9]{40})\b'
[regex]$regex_sha256 = '\b[a-f0-9]{64}\b'
[regex]$regex_md5 = '\b[a-f0-9]{32}\b'
[regex]$regex_domain = '([a-z0-9]+\.)*[a-z0-9]+\.[a-z]+'
[regex]$regex_selectURL = '^(\/(.*))'
[regex]$regex_hash = '((?<!FIRSTBYTES:\s)|[\b\s]|^)([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(\b|$)'


function WriteCSV() {
    param (
         $query_info,
         $verbose = $true
     )

    ForEach($type in $query_info.detection_type) {
        $detection_type_str += ("$type`n")
    }
    
    $csv = [pscustomobject]@{
        'Query' = $query_info.query
        'File Name' = $query_info.file_name
        'Rating' = $query_info.rating
        'Comments' = $query_info.comments
        'Reports' = $query_info.reports
        'Detection Type' = $detection_type_str
        'First Seen' = $query_info.first_seen
        'Last Seen' = $query_info.last_seen
        'Link' = $query_info.link
        'MD5' = $query_info.md5
        'SHA-1' = $query_info.sha1
        'SHA-256' = $query_info.sha256
    }
    
    if (!(Test-Path ".\Reports" -PathType Container)) {
        [void](New-Item -ItemType Directory -Force -Path ".\Reports")
    }
    if($current_filename -eq '') {
        $time = (Get-Date -Format "dd-MM-yy hh-mm-ss")
        $global:current_filename = (".\IOC_Report - $time.csv")
        $csv | Export-Csv -Path ".\Reports\$current_filename" -NoTypeInformation -Force 
    }
    else {
        $csv | Export-Csv -Path ".\Reports\$current_filename" -NoTypeInformation -Append
    }
    
    if($verbose) {
        OutputHandler ("[$] [" + ($query_info.platform) + "] [" + $query_info.ioc_type + $query_info.hash_type + "] " + $query_info.query + "`t" + $query_info.rating +"`t" + $query_info.detection_type[0])
    }
    
    if($temp_cache_check) {
        Add-Content -Path $temp_cache_file -Value $query_info.query
    }
}


function OutputHandler($message, $type) {
    switch ($type) {
        1 { $output = ("[!] [" + $message.platform + "] Quota Exceeded [!] : " + $message.query); break }
        2 { $output = ("[!] [" + $message.platform + "] [" + $message.ioc_type + "] " + $message.query + ": " + $message.rating + ", checking other platforms..."); break }
        3 { $output = ("[!] [" + $message.platform + "] Bad request [!] : " + $message.query); break }
        4 { $output = ("[?] Invalid IOC: " + $message.query);break }
        Default { $output = $message }
    }
    $output | Out-File -FilePath .\log.txt -Append
    $output | Write-Host
}


function Kaspersky-Check($query_info) {
    $query_info.platform = 'Kaspersky'
    $query_info.link = ("https://opentip.kaspersky.com/" + $query_info.query)
    $kaspersky_body.request = $query_info.query
    
    try {
        $response = Invoke-RestMethod -Uri ($kaspersky_url + $kaspersky_url_type.($query_info.ioc_type)) -Headers $kaspersky_headers -Body $kaspersky_body

        if($query_info.ioc_type -ne 'hash') {
            if($response.Zone -eq 'Red') {
                $query_info.rating = 'Malicious'
            }
            elseif($response.Zone -eq 'Green') {
                $query_info.rating = 'Clean'
            }
            elseif($response.Zone -eq 'Grey') {
                $query_info.rating = 'Unknown'
            }
        }
        
        else {
            $query_info.rating = $response.FileGeneralInfo.FileStatus
        }
        
        $query_info.first_seen = $response.FileGeneralInfo.FirstSeen
        $query_info.last_seen = $response.FileGeneralInfo.LastSeen
        
        if($response.FileGeneralInfo.Signer -eq "Microsoft Corporation") {
            $query_info.comments = "Microsoft Corporation. All rights reserved."
        }

        ForEach($detection in $response.DetectionsInfo) {
            if($query_info.detection_type[0] -eq '-') {
                $query_info.detection_type[0] = $detection.DetectionName
            }
            else {
                [void]$query_info.detection_type.Add($detection.DetectionName)
            }
        }
        
        if($query_info.detection_type[0] -ne '-') {
            $query_info.reports = 100
        }

        WriteCSV $query_info
    }
    catch {
        if($_.Exception.Response.StatusCode.Value__ -eq 403 -or $_.Exception.Response.StatusCode.Value__ -eq 429) {
            OutputHandler $query_info 1
            if((API-Toggle 2)) {
                Kaspersky-Check $query_info
                return
            }
        }
        elseif($_.Exception.Response.StatusCode.Value__ -eq 404 -or $response -eq '') {
            OutputHandler ("[!] [Kaspersky] Not found [!] : " + $query_info.query)
        }
        elseif($_.Exception.Response.StatusCode.Value__ -eq 400) {
            OutputHandler $query_info 3
        }
        else {
            OutputHandler ("[!] [Kaspersky] Error " + $_.Exception.Response.StatusCode.Value__ + "[!] : " + $query_info.query)
            OutputHandler $_.Exception
        }
        
        Fallback-Platform $query_info
    }
}


function AbuseIPDB-Check($query_info) {
    $query_info.platform = 'AbuseIPDB'
    $link = "https://www.abuseipdb.com/check/$query"
    $count_comments = 0
    $comment = '-'
    $abuseipdb_body.ipAddress = $query_info.query

    try {
        $response = Invoke-RestMethod -Uri $abuseipdb_url -Body $abuseipdb_body -Headers $abuseipdb_headers

        $whitelisted = $response.data.isWhitelisted
        $confidence_score = $response.data.abuseConfidenceScore
        $total_reports = $response.data.totalReports
        $query_info.last_seen = $response.data.lastReportedAt
        $isp = $response.data.isp
        $domain = $response.data.domain
        $usage_type = $response.data.usageType

        if($total_reports -eq 0 -and $confidence_score -eq 0) {
            $query_info.rating = 'Clean'
            OutputHandler $query_info 2
            Fallback-Platform $query_info
            return
        }
        elseif($total_reports -le 3 -and $confidence_score -le 10) {
            $query_info.rating = 'Suspicious'
        }
        elseif($total_reports -gt 3 -or $confidence_score -gt 10) {
            $query_info.rating = 'Malicious'
        }
        else {
            $query_info.rating = 'Unknown'
            OutputHandler $query_info 2
            Fallback-Platform $query_info
            return
        }
    
        ForEach($report in $response.data.reports) {
            if($count_comments -ge $abuseipdb_max_comments) {
                continue
            }
            $query_info.comments += ($report.comment + "`n")
            $count_comments += 1
        }

        WriteCSV $query_info
    }
    catch {
        OutputHandler ("[!] [AbuseIPDB] Error [!] : " + $query_info.query)
        OutputHandler $_.Exception
        Fallback-Platform $query_info
    }
}


function Fallback-Platform($query_info) {
    if($debug_platform -ne 0) {
        return
    }

    if($query_info.platform -eq $platforms.1) {
        if($query_info.ioc_type -eq 'ip') {
            AbuseIPDB-Check $query_info
        }
        elseif($query_info.ioc_type -eq 'hash' -or $query_info.ioc_type -eq 'domain') {
            Kaspersky-Check $query_info
        }
    }
    elseif($query_info.platform -eq $platforms.2) {
        if($query_info.ioc_type -eq 'domain') {
            AbuseIPDB-Check $query_info
        }
        else {
            WriteCSV $query_info
        }
    }
    elseif($query_info.platform -eq $platforms.4) {
        if($query_info.ioc_type -eq 'domain') {
            WriteCSV $query_info
        }
        else {
            Kaspersky-Check $query_info
        }
    }
    else {
        $query_info.comments = "UNKNOWN"
        WriteCSV $query_info
    }
}


function API-Toggle($platform) {
    
    if($platform -eq 1) {
        if($virustotal_keys.Count -gt ($virustotal_current_key + 1)) {
            $global:virustotal_current_key += 1
            $virustotal_headers.'x-apikey' = $virustotal_keys[$virustotal_current_key]
            OutputHandler "[!] [VirusTotal] Key Changed [!]"
            return $true
        }
        elseif($virustotal_keys.Count -le ($virustotal_current_key + 1)) {
            OutputHandler "[!] [VirusTotal] All keys exhausted [!]"
        }
    }
    elseif($platform -eq 2) {
        if($kaspersky_keys.Count -gt ($kaspersky_current_key + 1)) {
            $global:kaspersky_current_key += 1
            $kaspersky_headers.'x-api-key' = $kaspersky_keys[$kaspersky_current_key]
            OutputHandler "[!] [Kaspersky] Key Changed [!]"
            return $true
        }
        elseif($virustotal_keys.Count -le ($virustotal_current_key + 1)) {
            OutputHandler "[!] [Kaspersky] All keys exhausted [!]"
        }
    }
    return $false
}


function VirusTotal-Check($query_info) {
    $query_info.platform = 'VirusTotal'
    $query_info.link = "https://www.virustotal.com/gui/file/$query"
    
    try {
        $response = Invoke-RestMethod -Uri ($virustotal_url + $virustotal_url_type.($query_info.ioc_type) + $query_info.query) -Headers $virustotal_headers
        
        $count_malicious = $response.data.attributes.last_analysis_stats.malicious
        $count_suspicious = $response.data.attributes.last_analysis_stats.suspicious
        $query_info.file_name = $response.data.attributes.meaningful_name
        $sig_info = $response.data.attributes.signature_info
        $query_info.reports = $count_malicious + $count_suspicious

        if(![string]::IsNullOrWhitespace($response.data.attributes.first_submission_date)) {
            $query_info.first_seen = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($response.data.attributes.first_submission_date))
        }
        if(![string]::IsNullOrWhitespace($response.data.attributes.last_analysis_date)) {
            $query_info.last_seen = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($response.data.attributes.last_analysis_date))
        }

        ForEach($analysis in $response.data.attributes.last_analysis_results) {
            $analysis | Get-Member -MemberType NoteProperty | ForEach-Object {
                $key = $_.Name
                if($analysis.$key.category -eq 'malicious' -or $analysis.$key.category -eq 'suspicious') {
                    if($query_info.detection_type[0] -eq '-') {
                        $query_info.detection_type[0] = ($key + ":" + $analysis.$key.result)
                    }
                    else {
                        [void]$query_info.detection_type.Add($key + ":" + $analysis.$key.result)
                    }
                }
            }
        }

        if($query_info.reports -ge 3) {
            $query_info.rating = "Malicious"
        }
        elseif($query_info.reports -ge 1) {
            $query_info.rating = "Suspicious"
        }
        elseif($query_info.reports -eq 0) {
            $query_info.rating = "Clean"
            OutputHandler $query_info 2
            Fallback-Platform $query_info
            return
        }
        else {
            $query_info.rating = "Unknown"
            OutputHandler $query_info 2
            Fallback-Platform $query_info
            return
        }

        
        if($sig_info.copyright -eq "© Microsoft Corporation. All rights reserved.") {
                $query_info.comments = "Microsoft Corporation. All rights reserved"
        }

        WriteCSV $query_info
    }
    catch {
        if($_.Exception.Response.StatusCode.Value__ -eq 404) {
            OutputHandler ("[!] [VirusTotal] [" + $query_info.ioc_type + "] Not Found [!] : " + $query_info.query)
        }
        elseif($_.Exception.Response.StatusCode.Value__ -eq 429) {
            OutputHandler ("[!] [VirusTotal] [" + $query_info.ioc_type + "] Quota Exceeded, toggling keys... [!] : " + $query_info.query)
            if((API-Toggle 1)) {
                VirusTotal-Check $query_info
                return
            }
        }
        else {
            OutputHandler ("[!] [VirusTotal] Error " + $_.Exception.Response.StatusCode.Value__ + " [!] : " + $query_info.query)
            OutputHandler $_
        }

        Fallback-Platform $query_info
    }   
}


function QueryVerify($raw_query, $query_info) {
    $filtered_query = ''

    if([string]::IsNullOrWhitespace($raw_query) -or $raw_query.Contains('#')) {
        return $false
    }
    else {
        $filtered_query = $raw_query
        foreach($word in $filter_words) {
            $filtered_query = $filtered_query.Replace($word, '')
        }
        
        foreach($char in $split_chars) {
            $filtered_query = $filtered_query.split($char)[0]
        }

        if($filtered_query -match $regex_ipv4) {
            $query_info.ioc_type = 'ip'
        }
        elseif($filtered_query -match $regex_domain) {
            $query_info.ioc_type = 'domain'
        }
        elseif($filtered_query -match $regex_hash) {
            $query_info.ioc_type = 'hash'
            
            if($filtered_query -match $regex_sha1) {
                $query_info.hash_type = ':Sha1'
                $query_info.sha1 = $true
            }
            elseif($filtered_query -match $regex_sha256) {
                $query_info.hash_type = ':Sha256'
                $query_info.sha256 = $true
            }
            elseif($filtered_query -match $regex_md5) {
                $query_info.hash_type = ':MD5'
                $query_info.md5 = $true
            }
        }
        else {
            $query_info.query = $raw_query
            $query_info.comments = "Invalid IOC"
            WriteCSV $query_info $false
            OutputHandler $query_info 4
            return $false
        }
        $filtered_query = $Matches[0]

        if($temp_cache_check) {
            if(Test-Path -Path $temp_cache_file -PathType Leaf) {
                Get-Content $temp_cache_file | ForEach-Object {
                    if($_ -eq $filtered_query) {
                        return $false
                    }
                }
            }
        }

        $query_info.query = $filtered_query
    }
}

Write-Host ''
Write-Host "##################################################################";Write-Host ''
Write-Host "             V E R F   -    I O C   V E R I F I E R               ";Write-Host ''
Write-Host "##################################################################";Write-Host ''

if(!(Test-Path -Path $ioc_file -PathType Leaf)) {
    OutputHandler "[?] IOC File does not exist. Please create file `"$ioc_file`" with IOCs"
    return
}

Get-Content $ioc_file | ForEach-Object {
    $query_info = [query_class]::new()
    
    if((QueryVerify $_ $query_info) -eq $false) {
        return
    }
    
    switch ($debug_platform) {
        2 { Kaspersky-Check $query_info; break }
        4 { AbuseIPDB-Check $query_info; break }
        Default { VirusTotal-Check $query_info }
    }
}

# Delete Temporary cache file after script run
if((Test-Path -Path $temp_cache_file -PathType Leaf)) {
    Remove-Item $temp_cache_file
}
