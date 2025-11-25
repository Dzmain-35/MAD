rule Mal_Xeno_RAT
{
meta:
	description = "Identifies Xeno RAT malware"
strings: 
    $str1 = "xeno rat client"
	$str2 = "XenoManager"
	$str3 = "xeno_rat_client"
	$str4 = "xeno rat" nocase


condition:
  any of them
	
}

