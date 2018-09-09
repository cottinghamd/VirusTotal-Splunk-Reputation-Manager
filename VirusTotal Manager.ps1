#Script to interact with the Splunk KVStore and check hashes against VirusTotal
#This script requires some defaults for your environment to be configured if you want to use them

#blank out pre-configured defaults before storing in github
#convert to an executable

#Transforms.conf file is needed for the KVStore created by this script to be searchable in Splunk. Depending on the app you are using, please ensure the following transforms.conf entry exists

#[kvstorename]
#collection = kvstorename
#external_type = kvstore
#fields_list = hashtoquery,md5,permalink,positives,querydate,resource,response_code,scan_date,scan_id,scans,sha1,sha256,total,verbose_msg,_key

#Perform a certificate bypass, as we can't assume everyone has their Splunk web interface signed using a trusted certificate
Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
             ServicePoint srvPoint, X509Certificate certificate,
             WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
$vtapikey = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter your VirusTotal API key, click OK to use the default key","$env:vtapikey")
If($vtapikey -eq "")
{
#$vtapikey = "enterdefaultkeyhere"
write-host "Using default key $vtapikey"
} 

$outfile = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the location of the external logfile, click OK to use the default","$env:outfile")
If($outfile -eq "")
{
#write-host "Using the default log file location of [enterdefaultlogfilelocationhere]"
#$outfile = "[enterdefaultlogfilehere]" 
}

#this needs to be modified, so if no proxy is set the invoke-rest requests later don't use a proxy
$proxy = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the proxy address to use to contact VirusTotal in a server:port format, click OK to use the default","$env:proxy")
If($proxy -eq "")
{
#write-host "Using the default proxy of [proxyhere]"
#$proxy = "[proxyhere]"
}

$kvstorename = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the name of the KVStore you want to use, click OK to use the default","$env:kvstorename")
If($kvstorename -eq "")
{
write-host "Using the default KVStore name of file_reputation_lookup"
$kvstorename = "file_reputation_lookup"
}

$appcontext = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the name of the Splunk app the KVStore is located in, click OK to use the default of Search","$env:appcontext")
If($appcontext -eq "")
{
write-host "Using the default splunk app - Search"
$appcontext = "search"
}

$splunkserver = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the name of the Splunk server you want to connect to, in the format server:port, click OK to use the default of localhost","$env:splunkserver")
If($splunkserver -eq "")
{
write-host "Using the default Splunk server of localhost:8089"
$splunkserver = "localhost:8089"
}

$virustotalwait = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the wait time in seconds between virus total requests, click OK to use the default of 15 seconds (for the public VT API)","$env:virustotalwait")
If($virustotalwait -eq "")
{
write-host "Using the default VirusTotal wait time of 15 seconds to rate limit requests"
$virustotalwait = 15
}

$cred = Get-Credential

#get a list of all existing lookup tables in the search application context
$url = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/config"
try {$existinglookups = Invoke-RestMethod  -Uri $url -Credential $cred}
catch { $RestAuthError = $_.Exception }

#ensure we don't lock an account if the incorrect credentials are entered
If ($RestAuthError -ne $null)
{
	Write-Output "REST API Authentication Error Thrown, Aborting: $($RestAuthError.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host
    break
}
else
{
	write-host "Splunk Authentication OK"
}


If($existinglookups.title.Contains($kvstorename))
{
    #do nothing and continue
}
else
{
    #send a POST request to create a kv store called file_reputation_lookup
    write-host "KV Store $kvstorename does not exist, submitting request to create KVStore"
    $body = "name=$kvstorename"
    try { Invoke-RestMethod  -Method POST -Uri $url -body $body -Credential $cred}
    catch { $RestAuthError2 = $_.Exception }

    If ($RestAuthError2 -ne $null)
    {
	    Write-Output "REST API Error Thrown, Aborting: $($RestAuthError2.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host
    }
    else
    {
	    write-host "Created a KVStore Successfully" | Tee-Object -FilePath $outfile -Append | Write-Host
    }

    #define the kvstore schema and submit to Splunk
    $urlschema = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/config/$kvstorename"
    $kvstoreschema = 'field.hashtoquery=string','field.md5=string','field.sha256=string','field.positives=number','field.total=number','field.verbose_msg=string','field.permalink=string','field.scan_date=string','field.response_code=number','field.resource=string','field.sha1=string','field.scan_id=string','field.scans=string','field.querydate=string'
    foreach($i in $kvstoreschema)
        {
            try { Invoke-RestMethod  -Method POST -Uri $urlschema -body $i -Credential $cred}
            catch { $RestAuthError6 = $_.Exception }

            If ($RestAuthError6 -ne $null)
            {
                Write-Output "REST API Error Thrown, Aborting: $($RestAuthError2.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host
                break
            }
            else
            {
	           #do nothing, good job it worked, no need to print success in each line of the for loop
            }
        }
    write-host "This script has created a KVStore in Splunk called $kvstorename"
    write-host "NOTE: For this KVStore to be searchable in Splunk a transforms.conf needs to be created for it"
    wrote-host "Additionally, ensure the correct permissions are set on this KVStore for search"
}

#In this function the KVStore is downloaded, contents are parsed and other functions are called to do a lookup and submit values back to the KVStore
Function Work
{

#download URL KV Store. This will need to be filtered later
$urldownloadkv = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/data/$kvstorename"
try {$kvstorecontents = Invoke-RestMethod  -Uri $urldownloadkv -Credential $cred}
catch { $RestAuthError3 = $_.Exception }

If ($RestAuthError3 -ne $null)
{
	Write-Output "REST API Error Thrown, Aborting: $($RestAuthError3.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host
}
else
{
	Write-Output "Successfully downloaded the existing KVStore called $kvstorename"
}

#check for duplicate rows and attempt to delete them, this is a way to try and ensure that the KVStore doesn't fill up with Duplicates (as we can't control the database from here, we can't prevent suplicates from getting into the store in the first place)

#group entries in the store into duplicates
$kvstoreduplicates = $kvstorecontents |Group-Object -Property hashtoquery |Where Count -gt 1
If ($kvstoreduplicates -ne $null)
{
    #calculate the number of duplicates
    $kvstoredupcount = $kvstoreduplicates | Measure-Object -Sum -Property Count
    $kvstoredupcount = $kvstoredupcount.sum

    #store the number of groups to process for progress counter
    $kvstoretotalgroups = $kvstoreduplicates.count
    If ($kvstoredupcount -lt 250)
    {
        Write-Host "Warning, $kvstoredupcount duplicate entries were found in the KVStore, cleaning up" | Tee-Object -FilePath $outfile -Append | Write-Host
    }
    else
    {
        Write-Host "Warning, $kvstoredupcount duplicate entries were found in the KVStore, this will take some time to clean up. Please ensure all Splunk searches are checking for duplicates before populating the KVStore" | Tee-Object -FilePath $outfile -Append | Write-Host
    }

    
    #loop through each group that contains duplicate entries
    foreach ($i in $kvstoreduplicates)
    {
        $loopcounter++
        write-host "Progress:" ($loopcounter/$kvstoretotalgroups).tostring("P") "- Deduplicating hash value" $i.Name "this could take some time"
        #loop through each key, within each group. Skipping the first key as we don't want to completely remove that hashes entries from the KVStore completely
        foreach ($key in ($i.group | select -skip 1))
        {
            $keytodelete = $key._key
            $urldelete = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/data/$kvstorename/$keytodelete"
            try {$kvstoredeleteresponse = Invoke-RestMethod  -Method Delete -Uri $urldelete -Credential $cred}
            catch { $RestAuthError7 = $_.Exception }

            If ($RestAuthError7 -ne $null)
            {
	            Write-Output "Delete Reqeuest Error Thrown: $($RestAuthError5.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host
                $RestAuthError7 = $null
            }
            else
            {
	            #assume successful deletion
                #write-host "Successfully deleted key entry $keytodelete" | Tee-Object -FilePath $outfile -Append | Write-Host
            }
        }
    }

    #Because there were duplicates we need to re-download the store so we don't check for things that don't exist, so lets call the work function again before we continue
    Work
}
else
{
    #no duplicates to process, yay!
}

#get the current date and minus the number of days from it for the check in the next block
$datenow = (get-date).AddDays(-14)

#take the kvstore contents that have been downloaded and process each entry in the list
foreach($i in $kvstorecontents)
{
    #count the number of hashes to lookup and create the progress counter
    $kvstoretolookup = $kvstorecontents.count
    $loopcounter2++

    #This statement checks to see if there is a value in hashtoquery to lookup
    if($i.hashtoquery.length -ge 32)
    {
        #This statement checks to see if the querydate column has a date in it. We know that the date will be 10 characters total. If this is false it must be a new file that needs lookup, or bad date. I know there is a better way to do this.
        if($i.querydate.length -ne 10)
        {
            write-host "Progress:" ($loopcounter2/$kvstoretolookup).tostring("P") "- Hash value" $i.hashtoquery "has never been looked up before, this kvstore record has a key of" $i._key
            $VTReport = LookupHash -HashValue $i.hashtoquery
            SubmitJSONtoKVStore -VTReport $VTReport -KVStoreKey $i._key
        }
        #If we get here we should have a valid date, so then compare the current date (minus 14 days) with the date of the last query in query date. If this is true, it's time to re-look up the record.
        elseif($i.querydate -lt $datenow)
        {
            write-host "Progress:" ($loopcounter2/$kvstoretolookup).tostring("P") "- Hash value" $i.hashtoquery "has not been looked up in 14 days, re-processing, this kvstore record has a key of" $i._key
            $VTReport = LookupHash -HashValue $i.hashtoquery
            SubmitJSONtoKVStore -VTReport $VTReport -KVStoreKey $i._key
        }
    }
}
}



Function LookupHash
{
Param ($HashValue)

$body = @{ resource = $HashValue; apikey = $vtapikey }

#This checks before sending the request to VirusTotal if we are using a proxy or not, as the request needs modification 
If($proxy -ne "" -or $proxy -ne $null)
{
    try {$VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body -Proxy $proxy}
    catch { $RestAuthError4 = $_.Exception }

    If ($RestAuthError4 -ne $null)
    {
	    Write-Output "REST API Error Thrown, Aborting: $($RestAuthError4.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host
    }
    else
    {
	    write-host "Request to VirusTotal OK for hash $HashValue" | Tee-Object -FilePath $outfile -Append | Write-Host
    }
}
else
{
    try {$VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body}
    catch { $RestAuthError4 = $_.Exception }

    If ($RestAuthError4 -ne $null)
    {
	    Write-Output "REST API Error Thrown, Aborting: $($RestAuthError4.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host
    }
    else
    {
	    write-host "Request to VirusTotal OK for hash $HashValue" | Tee-Object -FilePath $outfile -Append | Write-Host
    }
}

#here we take the response from virustotal, get the current date and add it to the VirusTotal response so this can be indexed in the KVStore later
$date = Get-Date -format "dd-MM-yyyy"
$VTReport | Add-Member -Type NoteProperty -Name 'querydate' -Value $date
$VTReport | Add-Member -Type NoteProperty -Name 'hashtoquery' -Value $HashValue
$VTReport = $VTReport | ConvertTo-Json

#This is where the requests have a pause to ensure we don't exceed the VirusTotal API rate limit
write-host "Sleeping for $virustotalwait seconds, to rate limit requests" 
sleep -Seconds $virustotalwait

return $VTReport
}


Function SubmitJSONtoKVStore
{
Param ($VTReport,$KVStoreKey)

$urlupdatekv = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/data/$kvstorename/$KVStoreKey"
try {$kvstorekeyresponse = Invoke-RestMethod -Method Post -Uri $urlupdatekv -Body $VTReport -Credential $cred -ContentType 'application/json'}
catch { $RestAuthError5 = $_.Exception }

If ($RestAuthError5 -ne $null)
{
	Write-Output "REST API Authentication Error Thrown, Aborting: $($RestAuthError5.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host
}
else
{
	write-host "Successfully added VirusTotal response to KVStore"
}

return

}

#Keep the script alive by calling the function again when it finishes
While ($keepgoing -eq $null)
{
Work
write-host "Requests are up to date, waiting two minutes before checking the KVStore again"
sleep -Seconds 120
}


#This is just here for testing or if it's ever required
Function DeleteKVStore
{
$urlschemadelete = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/config/$kvstorename"
Invoke-RestMethod  -Method Delete -Uri $urlschemadelete -Credential $cred

}