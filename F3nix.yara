rule Mal_Fenix_Botnet
{
meta:
	description = "Identifies Fenix Botnet malware"
strings: 
	$str1 = "Success Stealer"
	$str2 = "steal.crypt"
	$str3 = "BotnetFenix.dll"
	$c21 = "zlvsiexj6d.d3vilsgg.xyz"
	$c22 = "149.248.77.62"
	$hash1 = "594804AA21887EE9D7B1B888F482D60C"
condition:
  any of them
	
}


