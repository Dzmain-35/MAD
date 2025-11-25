rule Mal_Latent_Bot
{
meta:
	description = "Identifies BazarLoader malware"
strings: 
    $str1 = "rdgate.$CLI-CRYPT"
	$str2 = "rdgate.$CLI-OBJM"
	$domain1 = "SERVEGAME.COM"

	
condition:
  any of them
	
}

