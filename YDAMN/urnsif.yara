rule Mal_Ursnif
{
meta:
	description = "Identifies Ursnif/Gozi malware"
strings: 
	$str1 = "modulo.cpl"
	$str5 = "inform.url"
	$str2 = "agenziaentrate"
	$str3 = "modulo.url"
	$str4 = "modulo.cpl"
	$c21 = "fotexion.com"
	$c22 = "104.21.88.20"
	$c23 = "62.173.146.110"
	$c24 = "172.67.171.248"
	$c25 = "62.173.146.108"
condition:
  any of them
	
}