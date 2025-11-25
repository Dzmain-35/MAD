rule Mal_ItarianRAT
{
meta:
	description = "Identifies ItarianRAT malware"
strings: 
    $str1 = "Itarian"
	$str2 = "Endpoint Manager"
	$str3 = "ITSM"
	$str4 = "RMM_Proxy"
	$str5 = "ApplicationFiles.RemotingHost.RHost.exe"
	$str6 = "ApplicationFiles.RemotingHost.RDesktop.exe"

condition:
  2 of them
	
}

