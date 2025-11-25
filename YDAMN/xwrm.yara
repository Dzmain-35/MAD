rule Mal_Xworm
{
meta:
	description = "Identifies Xworm malware"
strings: 
    $str1 = "freshinxworm.ddns.net"
	$str2 = "colmbat82.duckdns.org"
	$str3 = "XWorm"
	$str5 = "L_optReArmSku"
	$str6 = "futurist2.ddns.net"
	$str7 = "<Xwormmm>"
	$str8 = "XWorm V5.2"
	$str9 = "plat.zip"
	$domain1 = "xw9402may.duckdns.org"
	$domain2 = "dcxwq1.duckdns.org"
	$domain3 = "xw9402may.duckdns.org"
	$domain4 = "xwrmmone.duckdns.org"
	$ip1 = "154.53.51.233"
	$ip2 = "154.12.233.76"
	$ip3 = "91.207.57.115"
	$ip4 = "157.20.182.172"

	
condition:
  any of them
	
}

