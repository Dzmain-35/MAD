rule Mal_Snake_Keylogger
{
meta:
	description = "Identifies Snake_Keylogger malware"
strings:
	$str1 = "SnakeKeylogger"
	$str3 = "Snake Tracker"
	$str4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR1.0.3705;)"
	$ip1 = "77.81.142.87"
	$ip2 = "51.38.247.67"

condition:
  2 of them
	
}


rule Mal_Vip_Keylooger
{
meta:
	description = "Identifies VIP Keyloggermalware"
strings: 
    $str1 = "VIP Recovery"
	$str2 = "Keylogger"
	$str3 = "Recovered From"
condition:
  all of them
	
}


