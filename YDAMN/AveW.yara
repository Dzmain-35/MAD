rule Mal_AveMaria_or_WarZoneRAT
{
meta:
	description = "Identifies AverMaria/WarZaone RAT malware"
strings: 
	$str1 = "warzone160"
	$c21 = "makatti.duckdns.org"
	$c22 = "5.206.225.104"
	$c23 = "94.156.68.226"
condition:	
  any of them
	
}
