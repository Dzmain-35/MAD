rule Mal_Iris_Stealer
{
meta:
	description = "Identifies Iris malware"
strings: 
    $str1 = "script.irisstealer.xyz"
	$str2 = "irisstealer"

condition:
  any of them
	
}

