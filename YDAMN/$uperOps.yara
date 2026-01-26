rule Mal_SuperOps_RMM
{
meta:
	description = "Identifies SuperOps RMM malware"
strings: 
    $str1 = "superopsSetupExeFile"
	$str2 = "Superops RMM Agent"
	$str3 = "superops-install"
	$str4 = "SuperOps Installer"
	$domain1 = "superops.ai"
	$domain2 = "superops-wininstaller-prod.s3.us-east-2.amazonaws.com"

condition:
  any of them
	
}

