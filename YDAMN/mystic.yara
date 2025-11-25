rule Mal_Mystic
{
meta:
	description = "Identifies DarkGate malware"
strings: 
	$str1 = "loghub//master"
	$str2 = "SrartLoader"
	$str3 = "Gonna gather system information"
	$c21 = "5.42.92.211"
	$c22 = "77.91.124.55"
	
condition:
  any of them
}
