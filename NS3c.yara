rule Mal_NSecRTS
{
meta:
	description = "Identifies NSecRTS RAT malware"
strings: 
    $str1 = "NSEC"
	$str2 = "NSecRTX2.exe"
	$str3 = "Dev22.zip"
	$str4 = "NSEC-UID"
	$str5 = "X-NSEC-Authorization"
	$domain3 = "47.239.59.78"

condition:
  2 of them
	
}

