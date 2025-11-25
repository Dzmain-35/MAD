rule Mal_IcedID
{
meta:
	description = "Identifies IcedID malware"
strings: 
  	$str1 = "aprettopizza.world/live"
	$str2 = "peermangoz.me/live"
	$str3 = "nimeklroboti.info/live"
	
condition:
  any of them

}

