# VirusTotal-Splunk-Reputation-Manager
This is an application to assist with reputation lookups in Splunk. Put hashes into a KVStore, this application will monitor the KVStore and fetch the reputation results from VirusTotal.

Most of this code is managing rate limitations put in by VirusTotal using the community keys. If the key exceeds the 24 hour rate limit, it will sleep and wait until the key is unbanned again. 

This script requires some configuration within Splunk to work

A Transforms.conf file is needed for the KVStore created by this script to be searchable in Splunk. Depending on the app you are using, please ensure the following transforms.conf entry exists


[kvstorename]

collection = kvstorename

external_type = kvstore

fields_list = hashtoquery,md5,permalink,positives,querydate,resource,response_code,scan_date,scan_id,scans,sha1,sha256,total,verbose_msg,_key


This KVStore then needs to be populated with the hashes you need to lookup. hashes should be placed in the hashtoquery column. Hashes must be a minimum length of MD5. Also consider deduplicating events before adding to this KVStore in Splunk. The following search query provides an example:


index="indexname" | dedup hashes

| lookup file_reputation_lookup hashtoquery AS hashes output hashtoquery | search NOT hashtoquery="*"

| rename hashes as hashtoquery

| table hashtoquery

| outputlookup append=true file_reputation_lookup


The above search will take hashes from the index, deduplicate them, then find matches against the existing lookup table, ignore any entries that match something in the KVStore (already exists) and then put the remaining hashes in the lookup

The script also has a number of configuration options listed at the start of the script that are worth reviewing before use.
