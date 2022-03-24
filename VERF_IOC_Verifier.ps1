<#
    VERF - IOC Verifier
    Version : 1.1
    Creator : Dunura Dulshan | | https://github.com/ddulshan
    Description : Script to call Malware databases such as VirusTotal, Kaspersky and AbuseIPDB API for information on given query
#>

# Configurable Settings
$ioc_file = '.\ioc.txt'
$temp_cache_file = '.\VERF_Temp_Cache'
$debug_platform = 0 #0-debug off, 1-VT, 2-Kasper, 3-Intezer, 4-AbuseIPDB
$abuseipdb_max_comments = 8
$temp_cache_check = $true
$api_rate_limit = $false
$virustotal_timeout = 17
$filter_words = @('www.', '[', ']', 'http://', 'https://', 'hxxp://', 'hxxps://')

<# API KEYS
	Multiple keys supported. ie:
		
		$virustotal_keys = @(
			'XXXXX',
			'XXXXX',
			'XXXXX'
		)
#>
$virustotal_keys = @(
    ''
)
$kaspersky_keys = @(
    ''
)
$abuseipdb_keys = @(
    ''
)
$intezer_keys = @(
    ''
)

# Runtime Variables
$global:virustotal_current_key = 0
$global:kaspersky_current_key = 0
$global:absueipdb_current_key = 0
$global:intezer_current_key = 0
$global:current_filename = ''
$virustotal_key_exhausted = $false
$kaspersky_key_exhausted = $false
$intezer_key_exhausted = $false
$abuseipdb_key_exhausted = $false

# API URLs
$virustotal_url = "https://www.virustotal.com/api/v3/"
$kaspersky_url = "https://opentip.kaspersky.com/api/v1/search/"
$abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
$intezer_url = 'https://analyze.intezer.com/api/v2-0'

# Platform Dictionary
$platforms = @{
    1 = 'VirusTotal'
    2 = 'Kaspersky'
    3 = 'Intezer'
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

# Whitelisted signature list
$sig_whitelist = @('Microsoft Corporation')

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
$intezer_headers = @{
    'Authorization' = ''
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
$intezer_body = @{
    'api_key' = ''+$intezer_keys[$intezer_current_key]
}


# Regex for IOC identification
[regex]$regex_ipv4 = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
[regex]$regex_sha1 = '\b([a-f0-9]{40})\b'
[regex]$regex_sha256 = '\b[a-f0-9]{64}\b'
[regex]$regex_md5 = '\b[0-9a-fA-F]{32}\b'
[regex]$regex_domain = '([a-z0-9-]+\.)*[a-z0-9-]+\.[a-z]+'
[regex]$regex_selectURL = '^(\/(.*))'
[regex]$regex_hash = '((?<!FIRSTBYTES:\s)|[\b\s]|^)([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(\b|$)'


function WriteCSV($query_info, $verbose = $true) {

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
    Write-Host ''
    
    if($temp_cache_check) {
        Add-Content -Path $temp_cache_file -Value $query_info.query
    }
}


function OutputHandler($message, $type=0) {
    switch ($type) {
        2 { $output = ("[!] [" + $message.platform + "] [" + $message.ioc_type + $message.hash_type + "] " + $message.query + ": " + $message.rating + ", checking other platforms..."); break }
        Default { $output = $message }
    }
    $output | Out-File -FilePath .\log.txt -Append
    $output | Write-Host
}


function Fallback-Platform($query_info) {
    if($debug_platform -ne 0) {
        WriteCSV $query_info
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
        if($query_info.ioc_type -eq 'hash') {
            Intezer-Check $query_info
        }
        else {
            WriteCSV $query_info $false
        }
    }
    elseif($query_info.platform -eq $platforms.3) {
        WriteCSV $query_info $false
    }
    elseif($query_info.platform -eq $platforms.4) {
        if($query_info.ioc_type -eq 'domain') {
            WriteCSV $query_info $false
        }
        else {
            Kaspersky-Check $query_info
        }
    }
    else {
        WriteCSV $query_info $false
    }
}


function Update-IntezerToken {
    try {
        $token = (Invoke-RestMethod -Method "POST" -Uri ($intezer_url + '/get-access-token') -Body ($intezer_body | ConvertTo-Json) -ContentType "application/json").result
        $intezer_headers['Authorization'] = 'Bearer ' + $token
        OutputHandler ("[!] [" + $platforms.$platform + "] JWT Updated`n")
        return $true
    }
    catch {
        OutputHandler ("[?] [" + $platforms.$platform + "] Error retrieving JWT")
        return $false
    }
}


function Toggle-APIKey($platform) {
    $keys = ''
    $current_key = ''
    $key_hashtable = ''
    $key_value = ''
    $key_exhausted = ''
    
    switch ($platform) {
        1 { $keys = $virustotal_keys; $current_key = ([ref]$virustotal_current_key); $key_hashtable = $virustotal_headers; $key_value = 'x-apikey'; $key_exhausted = ([ref]$virustotal_key_exhausted); break }
        2 { $keys = $kaspersky_keys; $current_key = ([ref]$kaspersky_current_key); $key_hashtable = $kaspersky_headers; $key_value = 'x-api-key'; $key_exhausted = ([ref]$kaspersky_key_exhausted); break }
        3 { $keys = $intezer_keys; $current_key = ([ref]$intezer_current_key); $key_hashtable = $intezer_body; $key_value = 'api_key'; $key_exhausted = ([ref]$intezer_key_exhausted); break }
        4 { $keys = $abuseipdb_keys; $current_key = ([ref]$absueipdb_current_key); $key_hashtable = $abuseipdb_headers; $key_value = 'Key'; $key_exhausted = ([ref]$abuseipdb_key_exhausted); break }
        Default { break }
    }

    if($keys.Count -gt ($current_key.Value + 1)) {
        $current_key.Value += 1
        $key_hashtable.$key_value = $keys[$current_key.Value]
        OutputHandler ("[!] [" + $platforms.$platform + "] Key Changed`n")
        if($platform -eq 3) {
            [void](Update-IntezerToken)
        }

        return $true
    }
    elseif($keys.Count -le ($current_key.Value + 1)) {
        $key_exhausted.Value = $true
        OutputHandler ("[!] [" + $platforms.$platform + "] All keys exhausted`n")
    }

    return $false
}


function API-Request($query_info) {
    $platform = $platforms.GetEnumerator().Where({$_.Value -eq $query_info.platform}).Name
    
    do {
        try {
            if ($platform -eq 1) {
                if($virustotal_keys[$virustotal_current_key] -eq '' -or $virustotal_key_exhausted) {
                    break
                }
                $response = Invoke-RestMethod -Uri ($virustotal_url + $virustotal_url_type.($query_info.ioc_type) + $query_info.query) -Headers $virustotal_headers
                if($api_rate_limit) {
                    Start-Sleep -s $virustotal_timeout
                }
            }
            elseif ($platform -eq 2) {
                if($kaspersky_keys[$kaspersky_current_key] -eq '' -or $kaspersky_key_exhausted) {
                    
                    break
                }
                $response = Invoke-RestMethod -Uri ($kaspersky_url + $kaspersky_url_type.($query_info.ioc_type)) -Headers $kaspersky_headers -Body $kaspersky_body
            }
            elseif ($platform -eq 3) {
                
                if($intezer_keys[$intezer_current_key] -eq ''  -or $intezer_key_exhausted) {
                    break
                }
                if($intezer_headers['Authorization'] -eq '') {
                    if(!(Update-IntezerToken)) {
                        if((Toggle-APIKey $platform)) {
                            continue
                        }
                        break
                    }
                }
                $response = Invoke-RestMethod -Uri ($intezer_url + '/files/' + $query_info.query) -Headers $intezer_headers
            }
            elseif ($platform -eq 4) {
                if($abuseipdb_keys[$absueipdb_current_key] -eq ''  -or $abuseipdb_key_exhausted) {
                    break
                }
                $response = Invoke-RestMethod -Uri $abuseipdb_url -Body $abuseipdb_body -Headers $abuseipdb_headers
            }

            return $response
        }
        catch {
            if($_.Exception.Response.StatusCode.Value__ -eq 404 -or $_.Exception.Response.StatusCode.Value__ -eq 410) {
                OutputHandler ("[!] [" + $query_info.platform + "] [" + $query_info.ioc_type + $query_info.hash_type + "] Not Found : " + $query_info.query)
                break
            }
            elseif($_.Exception.Response.StatusCode.Value__ -eq 401) {
                OutputHandler ("[!] [" + $query_info.platform + "] Invalid or Expired Token")
                if(Update-IntezerToken) {
                    continue
                }
                else {
                    if((Toggle-APIKey $platform)) {
                        continue
                    }
                    break
                }
            }
            elseif($_.Exception.Response.StatusCode.Value__ -eq 400) {
                OutputHandler ("[!] [" + $query_info.platform + "] [" + $query_info.ioc_type + $query_info.hash_type + "] Bad request : " + $query_info.query)
                break
            }
            elseif($_.Exception.Response.StatusCode.Value__ -eq 429 -or $_.Exception.Response.StatusCode.Value__ -eq 403) {
                OutputHandler ("[!] [" + $query_info.platform + "] [" + $query_info.ioc_type + $query_info.hash_type + "] Quota Exceeded, toggling keys... : ")
                if((Toggle-APIKey $platform)) {
                    continue
                }
                break
            }
            else {
                OutputHandler ("[?] [" + $query_info.platform + "] Error " + $_.Exception.Response.StatusCode.Value__ + " : " + $query_info.query)
                OutputHandler ("[?] Check network connection, trying again...")
                Start-Sleep -s 5
                continue
            }
        }
    } while (1)
    
    Fallback-Platform $query_info

    return $false
}


function Intezer-Check($query_info) {
    $query_info.platform = 'Intezer'
    
    $response = API-Request($query_info)
    if(!$response) {
        return
    }

    if($response.status -eq 'succeeded') {
        $query_info.rating = $response.result.verdict
        $query_info.link = $response.result.analysis_url
        $query_info.detection_type[0] = $response.result.family_name
    }
    
    WriteCSV $query_info
}


function Kaspersky-Check($query_info) {
    $query_info.platform = 'Kaspersky'
    $kaspersky_body.request = $query_info.query
    
    $response = API-Request($query_info)
    if(!$response) {
        return
    }
    
    $query_info.link = ("https://opentip.kaspersky.com/" + $query_info.query)
    $query_info.first_seen = $response.FileGeneralInfo.FirstSeen
    $query_info.last_seen = $response.FileGeneralInfo.LastSeen
    
    foreach($sig in $sig_whitelist) {
        if($response.FileGeneralInfo.Signer -contains $sig) {
            $query_info.comments = $response.FileGeneralInfo.Signer
        }
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

    if($response.Zone -eq 'Red') {
        $query_info.rating = 'Malicious'
    }
    elseif($response.Zone -eq 'Green') {
        $query_info.rating = 'Clean'
        OutputHandler $query_info 2
        Fallback-Platform $query_info
        return
    }
    elseif($response.Zone -eq 'Grey') {
        $query_info.rating = 'Unknown'
        OutputHandler $query_info 2
        Fallback-Platform $query_info
        return
    }
    else {
        $query_info.rating = $response.FileGeneralInfo.FileStatus
    }
    
    WriteCSV $query_info
}


function AbuseIPDB-Check($query_info) {
    $query_info.platform = 'AbuseIPDB'
    $count_comments = 0
    $comment = '-'
    $abuseipdb_body.ipAddress = $query_info.query

    $response = API-Request($query_info)
    if(!$response) {
        return
    }

    $whitelisted = $response.data.isWhitelisted
    $confidence_score = $response.data.abuseConfidenceScore
    $total_reports = $response.data.totalReports
    $query_info.last_seen = $response.data.lastReportedAt
    $isp = $response.data.isp
    $domain = $response.data.domain
    $usage_type = $response.data.usageType
    $query_info.link = "https://www.abuseipdb.com/check/$query"


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


function VirusTotal-Check($query_info) {
    $query_info.platform = 'VirusTotal'
    
    $response = API-Request($query_info)
    if(!$response) {
        return
    }

    $count_malicious = $response.data.attributes.last_analysis_stats.malicious
    $count_suspicious = $response.data.attributes.last_analysis_stats.suspicious
    $query_info.file_name = $response.data.attributes.meaningful_name
    $sig_info = $response.data.attributes.signature_info
    $query_info.reports = $count_malicious + $count_suspicious
    $query_info.link = ("https://www.virustotal.com/gui/file/" + $query_info.query)


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

    foreach($sig in $sig_whitelist) {
        if($sig_info.copyright -contains $sig) {
            $query_info.comments = $sig_info.copyright
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

    WriteCSV $query_info
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
            OutputHandler ("[?] Invalid IOC: $raw_query (Filtered:$filtered_query)")
            WriteCSV $query_info $false
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
        3 { Intezer-Check $query_info; break }
        4 { AbuseIPDB-Check $query_info; break }
        Default { VirusTotal-Check $query_info }
    }
}

# Delete Temporary cache file after script run
if((Test-Path -Path $temp_cache_file -PathType Leaf)) {
    Remove-Item $temp_cache_file
}