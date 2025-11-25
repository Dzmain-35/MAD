rule Mal_Zoho_Assist_RAT
{
meta:
	description = "Identifies Zharkbot malware"
strings: 
    $str1 = "ZA_Connect.exe"
	$str2 = "ZAService.exe"
	$domain1 = "assist.zoho.com"
	$domain2 = "zoho.com/login/dummy"

condition:
  any of them
	
}

