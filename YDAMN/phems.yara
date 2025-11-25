rule Mal_PhemedroneStealer
{
meta:
	description = "Identifies Phemedrone Stealer malware"
strings: 
	$str1 = "https://t.me/reyvortex & https://t.me/TheDyer"
	$str2 = "Phemedrone"
	$ip1 = "51.79.185.145"
condition:
  any of them
	
}
