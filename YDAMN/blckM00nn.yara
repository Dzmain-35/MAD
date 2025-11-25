rule Mal_Black_Moon
{
meta:
	description = "Identifies Black Moon malware"
strings: 
	$str1 = "Tomcat.exe"
	$str2 = "E_Loader 1.0"
	$str3 = "https://github.com/ldcsaa/HP-Socket"
	$str4 = "blackmoon"
	$str5 = "WPS.lnk"
	$ip1 = "206.238.199.123"
	$ip2 = "203.107.1.33"
	$ip3 = "206.238.220.51"
	$ip4 = "154.55.135.78"

condition:
  2 of them
	
}	