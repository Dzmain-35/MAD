rule Mal_CyReX_RAT
{
meta:
	description = "Identifies CyReX_RAT malware"
strings: 
    $str1 = "CyReXRat"
	$str2 = "cyrex2.exe"

condition:
  any of them
	
}

