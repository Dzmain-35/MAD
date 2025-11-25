rule Mal_P0C0_RAT
{
meta:
	description = "Identifies P0C0 RAT malware"
strings: 
	$str1 = "Poco"
	$str2 = "poco-1.12.4-all"
	$ip1 = "94.131.119.126"
	
condition:
  2 of them
	
}	