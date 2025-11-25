rule Mal_Monitic_RMM
{
meta:
	description = "Identifies Monitic RMM malware"
strings: 
    $str1 = "Monitic"
	$str2 = "C:\\Program Files\\Monitic"
	$domain1 = "api.monitic.com"

condition:
  any of them
	
}

