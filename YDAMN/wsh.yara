rule Mal_WSH_RAT
{
meta:
    description = "Identifies WSH RAT malware"
strings:
	$str1 = "WSHRAT"
	$str2 = "is-ready"
	$ip1 = "2.59.254.205"
	$ip2 = "91.92.255.183"
	$domain1 = "wishpeople.duckdns.org"
	$hex1 = "57 53 48 52 41 54"
condition:
	any of them
}


