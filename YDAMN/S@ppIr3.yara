rule Mal_Sapphire_Rat
{
meta:
	description = "Identifies Sapphire Rat malware"
strings: 
    $str1 = "SapphireRAT1"	
	$str2 = "SapphireRAT"
condition:
  any of them
	
}

