rule Mal_Koi_Stealer
{
meta:
	description = "Identifies Koi info stealer malware"
strings: 
	$str1 = "i2p_init"
	$str2 = "peerProfiles"
	$str3 = "termsrv32.ini"
	$str4 = "i2p"
	
condition:
  2 of them
	
}


