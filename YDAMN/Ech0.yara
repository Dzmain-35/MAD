rule Mal_Echo_Rat
{
meta:
	description = "Identifies Echo Rat malware"
strings: 
    $str1 = "EchoRAT Server1"
	$str2 = "CN=EchoRAT Server"


condition:
  any of them
	
}

