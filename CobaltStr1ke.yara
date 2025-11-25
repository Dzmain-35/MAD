rule Mal_CobaltStrike
{
meta:
	description = "Identifies Cobalt Strike beacon malware"
strings: 
	$str1 = "HTTP/1.1 101 Switching Protocols"
	$ip1 = "159.75.57.69"
	$ip2 = "12.202.180.134"
	$ip3 = "192.197.113.45"
condition:
  2 of them
	
}


