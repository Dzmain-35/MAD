rule Mal_Koi_Stealer
{
meta:
	description = "Identifies Koi info stealer malware"
strings: 
	$str1 = "drollingly43.exe"
	$c2_1 = "lodovicicostruzioni.com"

	
condition:
  any of them
	
}