rule Mal_Ratty_RAT
{
meta:
	description = "Identifies RATTY malware"
strings: 
	$str1 = "ratty" nocase
	$str2 = "com/proj/client/logger/Logger"
	$str3 = "com.proj.client.Client"
	$str4 = "com/proj/client/Client.class"
	$str5 = "com/proj/client/logger/Logger/packet/packets/surveillance"
	$ip1 = "143.47.53.106"

condition:
  any of them
	
}
