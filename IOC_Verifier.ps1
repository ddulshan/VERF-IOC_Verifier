#Author : https://github.com/ddulshan
#Description : Script to call Malware databases such as VirusTotal, Kaspersky and AbuseIPDB API for information on given query

$virustotal_url = "https://www.virustotal.com/api/v3/"   
$kaspersky_url = "https://opentip.kaspersky.com/api/v1/search/" 
$abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"

$debug_platform = 1  #1-VT, 2-Kasper, 4-AbuseIPDB
$platforms = @{
    1 = 'VirusTotal'
    2 = 'Kaspersky'
    4 = 'AbuseIPDB'
    }

#QUERY    FILE-NAME    RATING    COMMENTS    REPORTS    DETECTION-TYPE    FIRST-SEEN    LAST-SEEN    LINK
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
    $ioc_type ='-'
    $hash_type = ''
    $platform = '-'
    $md5 = '-'
    $sha1 = '-'
    $sha256 = '-'

    query_class () {
        $this.detection_type.Add('-')
        }
}

$timeout = 17 #For VirusTotal query limit. 4/minute, 500/day

$virustotal_keys = @(
    '!!!!!!ADD VIRUSTOTAL API KEYS HERE!!!!!' #https://www.virustotal.com/gui/home/upload
    )
$global:virustotal_current_key = 0
$virustotal_headers = @{
    'x-apikey' = $virustotal_keys[$virustotal_current_key]
    }
$virustotal_url_type = @{
    'hash' = 'files/'
    'ip' = 'ip_addresses/'
    'domain' = 'domains/'
    }

$abuseipdb_headers = @{
    'Key' = '!!!!!!ADD ABUSEIPDB API KEYS HERE!!!!!' #https://www.abuseipdb.com/
    }
$abuseipdb_body = @{
    'ipAddress' = ''
    'maxAgeInDays' = '30'
    'verbose' = ''
    }
$abuseipdb_max_comments = 8 

$kaspersky_headers = @{
    'x-api-key' = "!!!!!!ADD KASPERSKY API KEYS HERE!!!!!" #https://opentip.kaspersky.com/
    }
$kaspersky_body = @{
    'request' = ""
    }
$kaspersky_url_type = @{
    'hash' = 'hash'
    'ip' = 'ip'
    'domain' = 'domain'
    }

[regex]$regex_ipv4 = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
[regex]$regex_hash = '^(((([a-z,1-9]+)|[0-9,A-Z]+))([^a-z\.]))*'
[regex]$regex_sha1 = '\b([a-f0-9]{40})\b'
[regex]$regex_sha256 = '\b[a-f0-9]{64}\b'
[regex]$regex_md5 = '\b[a-f0-9]{32}\b'
[regex]$regex_domain = '([a-z0-9]+\.)*[a-z0-9]+\.[a-z]+'

$global:current_filename = ''


function WriteCSV($query_info) {
    #QUERY    FILE-NAME    RATING    COMMENTS    REPORTS    DETECTION-TYPE    FIRST-SEEN    LAST-SEEN    LINK    MD5    SHA-1    SHA-256
    
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
    
    OutputHandler ("[$] [" + ($query_info.platform) + "] [" + $query_info.ioc_type + $query_info.hash_type + "] " + $query_info.query + "`t" + $query_info.rating +"`t" + $query_info.detection_type[0])
    }


function OutputHandler($message, $type) {
    if($type -eq 1) { #Quota Exceed
        $output = ("[!] [" + $message.platform + "] Quota Exceeded [!] : " + $message.query)
        }
    elseif($type -eq 2) { #Other Platform check
        $output = ("[!] [" + $message.platform + "] [" + $message.ioc_type + "] " + $message.query + ": " + $message.rating + ", checking other platforms...")
        }
    elseif($type -eq 3) { #Bad request
        $output = ("[!] [" + $message.platform + "] Bad request [!] : " + $message.query)
        }
    else {
        $output = $message
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

        $query_info.rating = $response.FileGeneralInfo.FileStatus
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
            Fallback-Platform $query_info
            }
        elseif($_.Exception.Response.StatusCode.Value__ -eq 404 -or $response -eq '') {
            OutputHandler ("[!] [Kaspersky] Not found [!] : " + $query_info.query)
            Fallback-Platform $query_info
            }
        elseif($_.Exception.Response.StatusCode.Value__ -eq 400) {
            OutputHandler $query_info 3
            Fallback-Platform $query_info
            }
        else {
            OutputHandler ("[!] [Kaspersky] Error " + $_.Exception.Response.StatusCode.Value__ + "[!] : " + $query_info.query)
            OutputHandler $_.Exception
            Fallback-Platform $query_info
            }
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
    elseif($query_info.platform -eq $platforms.3) {
        WriteCSV $query $unknown $unknown $unknown $unknown $unknown $unknown $unknown $unknown $null $ioc_type
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


function API-Toggle {
    if($virustotal_keys.Count -gt ($virustotal_current_key + 1)) {
        $global:virustotal_current_key += 1
        $virustotal_headers.'x-apikey' = $virustotal_keys[$virustotal_current_key]
        OutputHandler "[!] [VirusTotal] Key Changed [!]"
        return $true
        }
    elseif($list.Count -le ($virustotal_current_key + 1)) {
        OutputHandler "[!] [VirusTotal] All keys exhausted [!]"
        }
    return $false
    }


function VirusTotal-Check($query_info) {
    $query_info.platform = 'VirusTotal'
    
    try {
        $response = Invoke-RestMethod -Uri ($virustotal_url + $virustotal_url_type.($query_info.ioc_type) + $query_info.query) -Headers $virustotal_headers
            
        $count_malicious = $response.data.attributes.last_analysis_stats.malicious
        $count_suspicious = $response.data.attributes.last_analysis_stats.suspicious
        $query_info.file_name = $response.data.attributes.meaningful_name
        $sig_info = $response.data.attributes.signature_info
        $query_info.link = "https://www.virustotal.com/gui/file/$query"
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
            if(API-Toggle) {
                VirusTotal-Check $query_info
                return
                }
            }
        else {
            OutputHandler ("[!] [VirusTotal] Error " + $_.Exception.Response.StatusCode.Value__ + " [!] : " + $query_info.query)
            OutputHandler $_.Exception
            }

        Fallback-Platform $query_info
        }   
    }


function QueryVerify($raw_query, $query_info) {
    if([string]::IsNullOrWhitespace($raw_query) -or $raw_query.Contains('#')) {
        $query_info.query = $false
        return 
        }
    else {
        $query_info.query = $raw_query.Replace('[', '').Replace(']', '').Replace('https://', '').Replace('http://', '').Replace('www.', '')

        if($query_info.query -match $regex_ipv4) {
            $query_info.ioc_type = 'ip'
            }
        elseif($query_info.query -match $regex_domain) {
            $query_info.ioc_type = 'domain'
            }
        elseif($query_info.query -match $regex_hash) {
            $query_info.ioc_type = 'hash'
            
            if($query_info.query -match $regex_sha1) {
                $query_info.hash_type = ':Sha1'
                $query_info.sha1 = $true
                $query_info.sha256 = $false
                $query_info.md5 = $false
                }
            elseif($query_info.query -match $regex_sha256) {
                $query_info.hash_type = ':Sha256'
                $query_info.sha1 = $false
                $query_info.sha256 = $true
                $query_info.md5 = $false
                }
            elseif($query_info.query -match $regex_md5) {
                $query_info.hash_type = ':MD5'
                $query_info.sha1 = $false
                $query_info.sha256 = $false
                $query_info.md5 = $true
                }
            else {
                $query_info.sha1 = $false
                $query_info.sha256 = $false
                $query_info.md5 = $false
                }
            }
        else {
            WriteCSV $query_info.query "Invalid IOC"
            }
        }
    }


Get-Content ./ioc.txt | ForEach-Object {
    $query_info = [query_class]::new()
    QueryVerify $_ $query_info #$query_info.query, $query_info.ioc_type, $query_info.hash_type =

    if($query_info.query -eq $false) {
        return
        }
    if($debug_platform -eq 1) {
        VirusTotal-Check $query_info
        }
    elseif($debug_platform -eq 2) {
        Kaspersky-Check $query_info
        }
    elseif($debug_platform -eq 4) {
        AbuseIPDB-Check $query_info
        }
    }

