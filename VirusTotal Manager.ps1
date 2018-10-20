#Script to interact with the Splunk KVStore and check hashes against VirusTotal

#A Transforms.conf file is needed for the KVStore created by this script to be searchable in Splunk. Depending on the app you are using, please ensure the following transforms.conf entry exists

#[kvstorename]
#collection = kvstorename
#external_type = kvstore
#fields_list = hashtoquery,md5,permalink,positives,querydate,resource,response_code,scan_date,scan_id,scans,sha1,sha256,total,verbose_msg,_key

#If you want to hard code the following default options for your script and not ask questions upon launch, please set the following variables:
#$vtapikey = "putkeyhere"
#$outfile = "D:\logfile.txt"
#$proxy = "http://proxy:port"
#$kvstorename = "file_reputation_lookup"
#$appcontext = "search"
#$splunkserver = "localhost:8089"
#$virustotalwait = 12
#$debuglogging = "no"
#$lookuprestartthreshold = 250
#$lookupagethreshold = 14
#$dateformat = "dd-MM-yyyy"
#$deduplicateenable = "no"
#$staggerdededuplicate = "10"

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

If ($vtapikey -eq $null)
{
	$vtapikey = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter your VirusTotal API key, click OK to use the default key", "$env:vtapikey")
	If ($vtapikey -eq "")
	{
		write-host "Using default key $vtapikey"
		If ($vtapikey -eq "")
		{
			Write-Host "No VirusTotal API Key was entered, aborting"
			Break
		}
	}
}

If ($outfile -eq $null)
{
	$outfile = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the location of the external logfile, click OK to use the default", "$env:outfile")
	If ($outfile -eq "")
	{
		write-host "Using the default log file location of $outfile"
		If ($outfile -eq "")
		{
			Write-Host "No Default Log File Location was entered, aborting"
			Break
		}
	}
}

If ($proxy -eq $null)
{
	$proxy = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the proxy address to use to contact VirusTotal in a server:port format, click OK to use no proxy", "$env:proxy")
	If ($proxy -eq "")
	{
		write-host "Not using a proxy for VirusTotal lookups"
	}
}

If ($kvstorename -eq $null)
{
	$kvstorename = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the name of the KVStore you want to use, click OK to use the default of file_reputation_lookup", "$env:kvstorename")
	If ($kvstorename -eq "")
	{
		write-host "Using the default KVStore name of file_reputation_lookup"
		$kvstorename = "file_reputation_lookup"
	}
}

If ($appcontext -eq $null)
{
	$appcontext = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the name of the Splunk app the KVStore is located in, click OK to use the default of Search", "$env:appcontext")
	If ($appcontext -eq "")
	{
		write-host "Using the default splunk app - Search"
		$appcontext = "search"
	}
}

If ($splunkserver -eq $null)
{
	$splunkserver = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the name of the Splunk server you want to connect to, in the format server:port, click OK to use the default of localhost:8089", "$env:splunkserver")
	If ($splunkserver -eq "")
	{
		write-host "Using the default Splunk server of localhost:8089"
		$splunkserver = "localhost:8089"
	}
}

If ($virustotalwait -eq $null)
{
	$virustotalwait = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the wait time in seconds between virus total requests, click OK to use the default of 15 seconds (for the public VT API)", "$env:virustotalwait")
	If ($virustotalwait -eq "")
	{
		write-host "Using the default VirusTotal wait time of 15 seconds to rate limit requests"
		$virustotalwait = 15
	}
}

If ($lookuprestartthreshold -eq $null)
{
	$lookuprestartthreshold = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the number of VirusTotal re-checks you want to perform before re-checking for new hashes. Click OK to use the default of 250", "$env:lookuprestartthreshold")
	If ($lookuprestartthreshold -eq "")
	{
		write-host "Using the default re-check value of 250. This will perform VirusTotal updates on existing hashes for about an hour using the free VT API before checking for new hashes again"
		$lookuprestartthreshold = 250
	}
}

If ($lookupagethreshold -eq $null)
{
	$lookupagethreshold = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the age threshold in days for VirusTotal re-checks. For example, entering 21 will re-check all entries older than three weeks. Click OK to use the default of 14", "$env:lookupagethreshold")
	If ($lookupagethreshold -eq "")
	{
		write-host "Using the default age threshold of 14. This will re-check VirusTotal lookups that have not been updated in two weeks."
		$lookupagethreshold = 14
	}
}

If ($debuglogging -eq $null)
{
	$debuglogging = [Microsoft.VisualBasic.Interaction]::InputBox("Please type yes/no to disable or enable debug logging.", "$env:debuglogging")
	If ($debuglogging -eq "")
	{
		write-host "Using the default debug logging of no"
		$debuglogging = "no"
	}
}

If ($deduplicateenable -eq $null)
{
	$deduplicateenable = [Microsoft.VisualBasic.Interaction]::InputBox("Please type yes/no to disable or enable deduplication. If you are performing deduplication of the KVStore in Splunk say no to this question", "$env:deduplicateenable")
	If ($deduplicateenable -eq "")
	{
		write-host "Using the default deduplication of yes"
		$deduplicateenable = "yes"
	}
}

If ($staggerdededuplicate -eq $null)
{
	$staggerdededuplicate = [Microsoft.VisualBasic.Interaction]::InputBox("If you want to stagger deduplication across runs, please enter the number of runs you want to skip. If you want to deduplicate upon every run, please enter 1 here", "$env:staggerdededuplicate")
	If ($staggerdededuplicate -eq "")
	{
		write-host "Using the default stagger of 10 to perform a deduplication every 10 runs"
		$staggerdededuplicate = "10"
	}
}


$cred = Get-Credential

#get a list of all existing lookup tables in the search application context
$url = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/config"
try { $existinglookups = Invoke-RestMethod -Uri $url -Credential $cred }
catch { $RestAuthError = $_.Exception }

#ensure we don't lock an account if the incorrect credentials are entered
If ($RestAuthError -ne $null)
{
	Write-Output "Splunk REST API - Could not authenticate, Aborting: $($RestAuthError.Message)" | Tee-Object -FilePath $outfile | Write-Host -ForegroundColor Red
	break
}
else
{
	Write-Output "Splunk Authentication OK" | Tee-Object -FilePath $outfile | Write-Host
}


If ($existinglookups.title.Contains($kvstorename))
{
	#do nothing and continue
}
else
{
	#send a POST request to create a kv store called file_reputation_lookup
	write-host "KV Store $kvstorename does not exist, submitting request to create KVStore"
	$body = "name=$kvstorename"
	try { Invoke-RestMethod -Method POST -Uri $url -body $body -Credential $cred }
	catch { $RestAuthError2 = $_.Exception }
	
	If ($RestAuthError2 -ne $null)
	{
		Write-Output "Splunk REST API - Error creating a KVStore, Aborting: $($RestAuthError2.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host -ForegroundColor Red
		break
	}
	else
	{
		Write-Output "Created a KVStore Successfully" | Tee-Object -FilePath $outfile -Append | Write-Host
	}
	
	#define the kvstore schema and submit to Splunk
	$urlschema = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/config/$kvstorename"
	$kvstoreschema = 'field.hashtoquery=string', 'field.md5=string', 'field.sha256=string', 'field.positives=number', 'field.total=number', 'field.verbose_msg=string', 'field.permalink=string', 'field.scan_date=string', 'field.response_code=number', 'field.resource=string', 'field.sha1=string', 'field.scan_id=string', 'field.scans=string', 'field.querydate=string'
	foreach ($i in $kvstoreschema)
	{
		try { Invoke-RestMethod -Method POST -Uri $urlschema -body $i -Credential $cred }
		catch { $RestAuthError6 = $_.Exception }
		
		If ($RestAuthError6 -ne $null)
		{
			Write-Output "Splunk REST API - Error when defining the KVStore schema, Aborting: $($RestAuthError6.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host -ForegroundColor Red
			break
		}
		else
		{
			#do nothing, good job it worked, no need to print success in each line of the for loop
		}
	}
	write-host "This script has created a KVStore in Splunk called $kvstorename"
	write-host "NOTE: For this KVStore to be searchable in Splunk a transforms.conf needs to be created for it"
	write-host "Additionally, ensure the correct permissions are set on this KVStore for search"
}

#In this function the KVStore is downloaded, contents are parsed and other functions are called to do a lookup and submit values back to the KVStore
Function PerformUpdates
{
	#download URL KV Store. Use Splunk to sort the kvstore by hash value to try and make grouping faster later.
	#We need to download the kvstore in chunks here, because the Rest API has a 50,000 result limit
	$query = "fields=hashtoquery,querydate,response_code,_key"
	$query2 = "limit=50000"
	
	while ($kvstorechunk.count -eq '50000' -or $kvstorecontents -eq $null)
	{
		$chunkcounter++
		$skipvalue = $chunkcounter * '50000'
		$query3 = "skip=$skipvalue"
		
		If ($debuglogging -eq "yes")
		{ Write-Output "Skip value is" $skipvalue }
		
		$kvstorequery = $kvstorename + "?" + $query + "&" + $query2 + "&" + $query3
		$urldownloadkv = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/data/$kvstorequery"
		try { $kvstorechunk = Invoke-RestMethod -Uri $urldownloadkv -Credential $cred }
		catch { $RestAuthError3 = $_.Exception }
		
		If ($RestAuthError3 -ne $null)
		{
			Write-Output "Splunk REST API - Error when downloading the KVStore, attempting to download again: $($RestAuthError3.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host -ForegroundColor Red
			$chunkcounter - 1
			$errorcounter++
			If ($errorcounter -ge 4)
			{
				Write-Output "there were multiple errors downloading the KVStore exiting"
				break
			}
		}
		else
		{
			$kvstorecontents = $kvstorecontents + $kvstorechunk
			If ($debuglogging -eq "yes")
			{ Write-Output "Successfully downloaded a chunk of the KVStore called $kvstorename, the KVStore now has" $kvstorecontents.count "entries in it." }
		}
	}
	
	
	Write-Host "There are" $kvstorecontents.count "entries in the KVStore"
	
	#count the number of items to lookup for the progress counter
	$kvstoretolookup = $kvstorecontents.count
	
	Write-Host "Checking for hash values that have not been looked up before"
	
	#define batch query as an array for population later
	$batchquery = @()
	#take the kvstore contents that have been downloaded and process each entry in the list for new hash values
	foreach ($i in $kvstorecontents)
	{
		#increment the progress counter
		$loopcounter2++
		
		#This statement checks to see if there is a value in hashtoquery to lookup
		if ($i.hashtoquery.length -ge 32)
		{
			#If there is no response code against the hash, look it up. It may not have been looked up before or previously failed.
			if ($i.response_code -ne "0" -and $i.response_code -ne "1")
			{
				write-host "Progress:" ($loopcounter2/$kvstoretolookup).tostring("P") "- Hash value" $i.hashtoquery "does not have a result, performing lookup."

				#This is where we need to gather four of these hashes to perform a batch query against VirusTotal (four is the maximum supported at once on the free API key)
				$batchquery += New-Object PSObject -Property (@{ Hash = $i.hashtoquery; KVStoreKey = $i._key })
				if ($batchquery.Count -eq 4)
				{
					#when the array is four hashes big send it over to the lookup hash function for lookup
					If ($debuglogging -eq "yes") { Write-Output "batch query is" $batchquery | Tee-Object -FilePath $outfile -Append | Write-Host }
					$VTReport = LookupHash -BatchQuery $batchquery
					
					$batchquery = @()
					If ($VTReport -ne $null)
					{
						If ($debuglogging -eq "yes") { Write-Output "VirusTotal Responses are" $VTReport | Tee-Object -FilePath $outfile -Append | Write-Host }
						
						#Take the virustotal report, for each response in the array, pull out the Splunk KVStore key and split it out for submission to the KVStore function
						$VTReport | ForEach-Object{
							$kvstorekey = $_ | Select-Object -Property KVStoreKey
							$kvstorekey = $kvstorekey.KVStoreKey
							$submittokv = $_ | Select-Object -Property * -ExcludeProperty KVStoreKey
							$submittokv = $submittokv | ConvertTo-Json
							SubmitJSONtoKVStore -VTReport $submittokv -KVStoreKey $kvstorekey
						}	
					}
					
				}
				
				
			}
			
		}
		
	}
	
	#reset the loop counter for the next run
	$loopcounter2 = $null
	Write-Host "Re-processing existing hash values that are stale"
	
	#take the kvstore contents that have been downloaded and sort the array by date, to make sure we are processing the oldest entries first
	$kvstorecontents = $kvstorecontents | Sort-Object { [datetime]::ParseExact($_.querydate, $dateformat, $null) } -ErrorAction SilentlyContinue
	#reset array to ensure it's clean
	$batchquery = @()
	foreach ($i in $kvstorecontents)
	{
		#increment the progress counter
		$loopcounter2++
		
		#This statement checks to see if there is a value in hashtoquery to lookup
		if ($i.hashtoquery.length -ge 32)
		{
			#If we get here we should have a hash that has previously been looked up before, this block checks to ensure it's a valid 10 character date'
			if ($i.querydate.length -eq 10)
			{
				#convert the querydate downloaded into a date format so we can compare it, also get the current time minus two weeks
				$lookupdate = $i.querydate
				$lookupdate = [datetime]::ParseExact($lookupdate, $dateformat, $null)
				$agethreshold = (get-date).AddDays(- $lookupagethreshold)
				
				#Check to see if the last date the lookup was performed was more than two weeks ago, if it is then look it up
				if ($lookupdate -lt $agethreshold)
				{
					#calculate the number of days between today and the last lookup date for a nice output message
					$stalelookupcount++
					$todaysactualdate = get-date
					$daysdifference = New-TimeSpan -Start $lookupdate -End $todaysactualdate
					write-host "Progress:" ($loopcounter2/$kvstoretolookup).tostring("P") "- Hash value" $i.hashtoquery "is" $daysdifference.Days "days old, re-processing."
					
					

				#This is where we need to gather four of these hashes to perform a batch query against VirusTotal (four is the maximum supported at once on the free API key)
					$batchquery += New-Object PSObject -Property (@{ Hash = $i.hashtoquery; KVStoreKey = $i._key })
					if ($batchquery.Count -eq 4)
					{
						#when the array is four hashes big send it over to the lookup hash function for lookup
						If ($debuglogging -eq "yes") { Write-Output "batch query is" $batchquery | Tee-Object -FilePath $outfile -Append | Write-Host }
						$VTReport = LookupHash -BatchQuery $batchquery
						
						$batchquery = @()
						If ($VTReport -ne $null)
						{
							If ($debuglogging -eq "yes") { Write-Output "VirusTotal Responses are" $VTReport | Tee-Object -FilePath $outfile -Append | Write-Host }
							
							#Take the virustotal report, for each response in the array, pull out the Splunk KVStore key and split it out for submission to the KVStore function
							$VTReport | ForEach-Object{
								$kvstorekey = $_ | Select-Object -Property KVStoreKey
								$kvstorekey = $kvstorekey.KVStoreKey
								$submittokv = $_ | Select-Object -Property * -ExcludeProperty KVStoreKey
								$submittokv = $submittokv | ConvertTo-Json
								SubmitJSONtoKVStore -VTReport $submittokv -KVStoreKey $kvstorekey
							}
						}
						
					}
				}
				#Make sure that these values don't get re-used in a future check
				$lookupdate = $null
				$agethreshold = $null
				$daysdifference = $null
				$todaysactualdate = $null
			}
			
		}
		#This will break out of the loop after a defined number of 'old' lookups have been updated. The reason you might want to do this is to ensure that new hashes are being looked up as a priority every so often.
		if ($stalelookupcount -ge $lookuprestartthreshold)
		{
			Clear-Host
			Write-Host "Restarting to check for new hashes, as $loopcounter2 existing re-checks have been performed"
			break
		}
	}
}

Function Deduplicate
{
	#download URL KV Store. Use Splunk to sort the kvstore by hash value to try and make grouping faster later.
	#We need to download the kvstore in chunks here, because the Rest API has a 50,000 result limit
	$query = "fields=hashtoquery,querydate,response_code,_key"
	$query2 = "limit=50000"
	
	while ($kvstorechunk.count -eq '50000' -or $kvstorecontents -eq $null)
	{
		$chunkcounter++
		$skipvalue = $chunkcounter * '50000'
		$query3 = "skip=$skipvalue"
		
		If ($debuglogging -eq "yes")
		{ Write-Output "Skip value is" $skipvalue }
		
		$kvstorequery = $kvstorename + "?" + $query + "&" + $query2 + "&" + $query3
		$urldownloadkv = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/data/$kvstorequery"
		try { $kvstorechunk = Invoke-RestMethod -Uri $urldownloadkv -Credential $cred }
		catch { $RestAuthError3 = $_.Exception }
		
		If ($RestAuthError3 -ne $null)
		{
			Write-Output "Splunk REST API - Error when downloading the KVStore, attempting to download again: $($RestAuthError3.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host -ForegroundColor Red
			$chunkcounter - 1
			$errorcounter++
			If ($errorcounter -ge 4)
			{
				Write-Output "there were multiple errors downloading the KVStore exiting"
				break
			}
		}
		else
		{
			$kvstorecontents = $kvstorecontents + $kvstorechunk
			If ($debuglogging -eq "yes")
			{ Write-Output "Successfully downloaded a chunk of the KVStore called $kvstorename, the KVStore now has" $kvstorecontents.count "entries in it." }
		}
	}
	
	
	Write-Host "There are" $kvstorecontents.count "entries in the KVStore"
	#check for duplicate rows and attempt to delete them, this is a way to try and ensure that the KVStore doesn't fill up with Duplicates (as we can't control the database from here, we can't prevent duplicates from getting into the store in the first place)
	#using Group-Object is extremely slow, this needs to be fixed in the future with a faster hash tables implementation?
	
	Write-Host "Performing KVStore deduplication, please wait"
	$kvstoreduplicates = $kvstorecontents | Group-Object -Property hashtoquery | Where Count -gt 1
	If ($kvstoreduplicates -ne $null)
	{
		#calculate the number of duplicates
		$kvstoredupcount = $kvstoreduplicates | Measure-Object -Sum -Property Count
		$kvstoredupcount = $kvstoredupcount.sum
		
		#store the number of groups to process for progress counter
		$kvstoretotalgroups = $kvstoreduplicates.count
		If ($kvstoredupcount -lt 100)
		{
			Write-Output "Warning, $kvstoredupcount duplicate entries were found in the KVStore, cleaning up" | Tee-Object -FilePath $outfile -Append | Write-Host
			$skip = "Yes"
		}
		else
		{
			Write-Output "Warning, $kvstoredupcount duplicate entries were found in the KVStore, this will take some time to clean up. Please ensure all Splunk searches are checking for duplicates before populating the KVStore" | Tee-Object -FilePath $outfile -Append | Write-Host
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
				try { $kvstoredeleteresponse = Invoke-RestMethod -Method Delete -Uri $urldelete -Credential $cred }
				catch { $RestAuthError7 = $_.Exception }
				
				If ($RestAuthError7 -ne $null)
				{
					Write-Output "Splunk REST API - Delete Reqeuest Error: $($RestAuthError7.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host -ForegroundColor Red
					$RestAuthError7 = $null
				}
				else
				{
					#assume successful deletion
					If ($debuglogging -eq "yes") { write-host "Successfully deleted key entry $keytodelete" }
				}
			}
		}
		
	}
	else
	{
		#no duplicates to process, yay!
		Write-Host "There are no duplicates in the KVStore"
	}
}


Function LookupHash
{
	Param ($batchquery)
	If ($debuglogging -eq "yes") { Write-Output "batch query on the other side is" $batchquery | Tee-Object -FilePath $outfile -Append | Write-Host }
	
	ForEach ($hash in $batchquery)
	{
		$count++
		If ($count -eq 4)
		{
			$submission += $hash.Hash
		}
		else
		{
			$submission += $hash.Hash + ", "
		}
	}
	
	If ($debuglogging -eq "yes") { Write-Output "submission string is" $submission | Tee-Object -FilePath $outfile -Append | Write-Host }
	$now = Get-Date -format "HH:mm"
	
	#This while loop ensures the Virustotal request succeeds and has four requests in the array
	$VTReport = $null
	While ($VTReport.Count -ne 4)
	{
		#This checks before sending the request to VirusTotal if we are using a proxy or not, as the request needs modification 
		If ($proxy -ne "" -or $proxy -ne $null)
		{
			try { $VTReport = Invoke-RestMethod -Method 'POST' -Uri "https://www.virustotal.com/vtapi/v2/file/report?resource=$submission&apikey=$vtapikey" -Proxy $proxy }
			catch { $RestAuthError4 = $_.Exception }
			
			If ($RestAuthError4 -ne $null)
			{
				Write-Output "$now - VirusTotal via Proxy - REST API Error, skipping KV submission of $submission : $($RestAuthError4.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host -ForegroundColor Red
				return $null
			}
			else
			{
				Write-Output "$now - Request to VirusTotal OK for hash $submission" | Tee-Object -FilePath $outfile -Append | Write-Host
			}
		}
		else
		{
			try { $VTReport = Invoke-RestMethod -Method 'POST' -Uri "https://www.virustotal.com/vtapi/v2/file/report?resource=$submission&apikey=$vtapikey" }
			catch { $RestAuthError4 = $_.Exception }
			
			If ($RestAuthError4 -ne $null)
			{
				Write-Output "$now - VirusTotal No Proxy - REST API Error, skipping KV submission of $submission : $($RestAuthError4.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host -ForegroundColor Red
				return $null
			}
			else
			{
				Write-Output "$now - Request to VirusTotal OK for hashes $submission" | Tee-Object -FilePath $outfile -Append | Write-Host
			}
		}
		
		#This is terrible code, I'm sorry. Quick bugfixing. Technically the while loop we are in should have fixed this. But I'm likely overlooking something
		If ($VTReport.Count -eq 4)
		{
			break
		}
		
		#This block is here to firstly retry the loop if there are bad requests. The second statement is here to break out of the loop if the request count isn't reached (for example the KVStore has ended and there are not 4 hashes to lookup)
		$vtnullcheck++
		If ($vtnullcheck -le 16)
		{
			$sleepyvirustotal = $vtnullcheck * $vtnullcheck * $vtnullcheck * 5
			Write-Output "VirusTotal Lookup Error, the VirusTotal response only had" $VTReport.Count "Row in it, typically this indicates a VirusTotal HTTP204 Response, rate limit exceeded. Sleeping for" $sleepyvirustotal "Seconds" | Tee-Object -FilePath $outfile -Append | Write-Host
			$VTReport = $null
			sleep -Seconds $sleepyvirustotal
		}
		ElseIf ($vtnullcheck -gt 16)
		{
			Write-Output "Didn't meet the successful response threshold, skipping. You could be temporarily banned from VirusTotal. Sleeping for six hours."
			$VTReport = $null
			$skippedlookup = "yes"
			return $null
			sleep -Seconds 21600
		}
	}
	
	#here we take the response from virustotal, get the current date and add it to the VirusTotal response so this can be indexed in the KVStore later
		$date = Get-Date -format $dateformat
		
		#This is probably a bad way to do this, but essentially we need to add the original request value and date to each response. Take the batchquery array and for each one, then look at the VT Reponse and append it to each response row.
		$rowcounter = 0
		
		ForEach ($hash in $batchquery)
		{
			$VTReport[$rowcounter] | Add-Member -Type NoteProperty -Name 'querydate' -Value $date
			$VTReport[$rowcounter] | Add-Member -Type NoteProperty -Name 'hashtoquery' -Value $hash.Hash
			$VTReport[$rowcounter] | Add-Member -Type NoteProperty -Name 'KVStoreKey' -Value $hash.KVStoreKey
			$rowcounter++
		}
		
		#This is where the requests have a pause to ensure we don't exceed the VirusTotal API rate limit
		If ($debuglogging -eq "yes")
		{ write-host "Sleeping for $virustotalwait seconds, to rate limit requests" }
		sleep -Seconds $virustotalwait
		
		return $VTReport
	}


Function SubmitJSONtoKVStore
{
	Param ($VTReport,
		$KVStoreKey)
	
	$urlupdatekv = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/data/$kvstorename/$KVStoreKey"
	try { $kvstorekeyresponse = Invoke-RestMethod -Method Post -Uri $urlupdatekv -Body $VTReport -Credential $cred -ContentType 'application/json' }
	catch { $RestAuthError5 = $_.Exception }
	
	If ($RestAuthError5 -ne $null)
	{
		Write-Output "Splunk REST API - Error submitting results to KVStore: $($RestAuthError5.Message)" | Tee-Object -FilePath $outfile -Append | Write-Host -ForegroundColor Red
	}
	else
	{
		Write-Host "Successfully added VirusTotal response to KVStore"
		
		If ($debuglogging -eq "yes"){
			write-host "KVStore key was $KVStoreKey"
			Write-Host "Contents Added Was" $VTReport}
	}

	return
	
}

#Keep the script alive by calling the function again when it finishes
While ($keepgoing -eq $null)
{
	
	#here we check if deduplication was enabled, if it is we also check the stagger setting to see how many runs deduplication should skip
	
	If ($deduplicateenable -eq "yes")
	{
		#count the number of times the program has completed
		$staggercounter++
		If ($staggercounter -gt $staggerdededuplicate)
		{
			#If the stagger counter has been reached, enable deduplication again and reset the stagger counter
			$staggercounter = 1
		}
		
		#Regardless of the above result, if it's the first run and deduplication is enabled we need to ensure deduplication is set to yes
		If ($staggercounter -eq 1)
		{
			Write-Host "Deduplicating"
			Deduplicate
		}
	}
	
	
	PerformUpdates
	$now = Get-Date -format "HH:mm"
	Write-Output "$now - Requests are up to date" | Tee-Object -FilePath $outfile -Append | Write-Host
	sleep -Seconds 120
	
	#This is here to check that Splunk communications are still ok and stop the application if Splunk is unable to be contacted
	$url = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/config"
	try { $existinglookups = Invoke-RestMethod -Uri $url -Credential $cred }
	catch { $RestAuthError9 = $_.Exception }
	
	#ensure we don't lock an account if the incorrect credentials are entered
	If ($RestAuthError9 -ne $null)
	{
		Write-Output "Splunk REST API - Authentication test failure, Aborting: $($RestAuthError9.Message)" | Tee-Object -FilePath $outfile | Write-Host -ForegroundColor Red
		break
	}
	else
	{
		#Assume everything is ok and keep going, blank the lookup store for running in a PowerShell interpreter
		$existinglookups = $null
	}
}


#This is just here for testing or if it's ever required
Function DeleteKVStore
{
	$urlschemadelete = "https://$splunkserver/servicesNS/nobody/$appcontext/storage/collections/config/$kvstorename"
	Invoke-RestMethod -Method Delete -Uri $urlschemadelete -Credential $cred
	
}
