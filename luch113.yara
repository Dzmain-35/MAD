rule Mal_Luchii_Logger
{
meta:
	description = "Identifies Luchii keylogger malware"
strings: 
    $str1 = "LuchiiSvet"
	$str2 = "102.135.95.102"

condition:
  any of them
	
}

