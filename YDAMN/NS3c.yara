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
	$str6 = "NSecRTS"
	$str7 = "NSecsoft.NativeModule.dll"
	$ip1 = "47.239.59.78"
	$ip2 = "134.122.200.242"
	$domain1 = "cloud.nsecsoft.com"

condition:
  2 of them
	
}
