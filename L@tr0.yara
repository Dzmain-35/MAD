rule Mal_Latrodectus
{
meta:
	description = "Identifies Lactrodectus malware"
strings: 
	$str1 = "isomicrotich.com"
	$str2 = "188.119.112.7"

condition:
  any of them
	
}


