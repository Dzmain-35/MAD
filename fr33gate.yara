rule Mal_FreeGate_Proxy
{
meta:
	description = "Identifies Freegate proxy that downloads further malware"
strings: 
    $str1 = "Freegate.exe"
	$str2 = "Freegate User Guide"
	$domain1 = "dongtaiwang.com"

condition:
  any of them
	
}

