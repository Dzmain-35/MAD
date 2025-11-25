rule Mal_Latrodectus
{
meta:
	description = "Identifies Latrodectus malware"
strings: 
	$str1 = "glosar\\beta.dll"
	$c21 = ", homq"
condition:
  any of them
	
}


