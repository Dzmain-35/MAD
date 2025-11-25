rule Mal_NjRAT
{
meta:
	description = "Identifies NJRAT malware"
strings: 
	$str1 = "njnjnjs.duckdns.org"
	$str2 = "junio2023.duckdns.org"
	$str3 = "154.12.254.215"
	$str4 = "njz.txt"
	$str5 = "mofers"
	$str6 = "NYAN CAT"
	$str7 = "nj.txt"
	$str8 = "dfasdfasdgs.duckdns.org"
	$ip1 = "46.246.86.16"
condition:
  any of them
	
}