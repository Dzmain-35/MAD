rule Mal_Mispadu
{
meta:
	description = "Identifies Mispadu malware"
strings: 
    $str1 = "geradcontsad.pro"
	$str2 = "contadcom.pro"
	$str3 = "pat2wx"
	$str4 = "contou infect"
	$domain1 = ".zapto.org"
	$domain2 = ".viewdns.net"
	$domain3 = "archivodzb.pro"
	$domain4 = "host.secureserver.net/g1/"
	$domain5 = "up.ddnsking.com"
	$ip1 = "91.92.244.191"
	$ip2 = "208.109.188.20"

	
condition:
  2 of them
	
}

