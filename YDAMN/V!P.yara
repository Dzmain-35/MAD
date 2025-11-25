rule Mal_Vip_Keylooger
{
meta:
	description = "Identifies VIP Keyloggermalware"
strings: 
    $str1 = "VIP Recovery"
	$str2 = /--------.+VIP Recovery.+ --------/

condition:
  any of them
	
}

