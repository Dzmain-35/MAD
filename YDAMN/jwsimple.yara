import "pe"


rule Mal_SimpleHelp_Jwrapper_RAT
{
meta:
	description = "Identifies Simplehelps j wrapper rat malware"
strings: 
    $str1 = "JWrapper"
	$str2 = "SimpleHelp"

condition:
  all of them
	
}



rule Mal_SimpleHelp_Jwrapper_IMPHASH
{
    meta:
        description = "Identifies CWRAT malware"
        imphash = "da7539752d4292fc084c7d813366cc8b"
    condition:
        pe.imphash() == "da7539752d4292fc084c7d813366cc8b"
}
