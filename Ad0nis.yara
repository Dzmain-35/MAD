rule Mal_Adon1s
{
meta:
	description = "Identifies Adon1s malware"
strings: 
	$str1 = "Adonis"
	$str2 = "Adonis_Pure"
	$ip1 = "154.47.22.45"
condition:
  any of them
	
}	