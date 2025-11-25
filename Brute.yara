rule Mal_ZharkBot
{
meta:
	description = "Identifies Zharkbot malware"
strings: 
	$str1 = "cronoze.com"
	$str2 = "pentium.php"
	$str3 = "muuxxu.com"
	$str5 = "95.100.156.164"
	$ip2 = "95.100.156.179"

condition:
  any of them
	
}

