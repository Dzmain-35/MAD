rule Mal_Phorpiex
{
meta:
	description = "Identifies Phorpiex malware"
strings: 
    $str1 = "twizt.net"
	$ip1 = "185.215.113.66"
	
	
condition:
  any of them
	
}

	