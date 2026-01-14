rule Mal_SuperOps_RMM
{
meta:
	description = "Identifies SuperOps RMM malware"
strings: 
    $str1 = "superopsSetupExeFile"
	  $str2 = "Superops RMM Agent"
	  $domain1 = "superops.ai"


condition:
  any of them
	
}

