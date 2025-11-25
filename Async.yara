rule Mal_Async_RAT
{
meta:
	description = "Identifies Async RAT malware"
strings: 
	$str1 = "AsyncRAT"
	$str2 = "con-ip.com"
	$str3 = "Server0"
	$domain1 = "robertocruzandradedomin.con-ip.com"
	$domain2 = "melo2024.kozow.com"
	$domain3 = "dios123.kozow.com"
	$domain4 = "andresrosado218.kozow.com"
	$domain5 = "ancy2024.kozow.com"
	$domain6 = "kozow.com"
	$domain7 = "modsmasync.duckdns.org"
	$domain8 = "envio1206.duckdns.org"
	$domain9 = "19nov2024.duckdns.org"
	$ip1 = "181.131.219.51"
	$ip2 = "45.40.96.97"
	$ip3 = "191.88.249.120"
	$ip4 = "104.156.247.38"
	$ip5 = "179.14.8.215"
	
condition:
  2 of them
	
}	