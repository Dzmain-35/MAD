rule Mal_StealC
{
meta:
	description = "Identifies StealC malware"
strings: 
	$c21 = "94.130.34.158"
	$str1 = "C:\\builder_v2\\stealc\\json.h"
	
condition:
  any of them
	
}


