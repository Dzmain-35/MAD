rule Mal_Sakura_RAT
{
meta:
	description = "Identifies Sakura Remote Access malware"
strings: 
    $str1 = "SAKURA RAT v1.0"
	$str2 = "SAKURAVIP1"
	$str3 = "SAKURA.exe"

condition:
  any of them
	
}

