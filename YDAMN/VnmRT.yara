rule Mal_VenomRAT
{
meta:
	description = "Identifies VenomRAT malware"
strings: 
	$str2 = "qwqdanchun"
	$str3 = /VenomRAT Server1.+/
	$ip1 = "12.202.180.134"
condition:
  2 of them
	
}


rule Mal_VenomRAT_Chaos_Variant
{
meta:
	description = "Identifies VenomRAT Chaos variant malware"
strings: 
	$str2 = "VenomC.Chaos"
	$str3 = "Venom\\DarkEye\\"
	$ip1 = "45.158.8.240"
condition:
  any of them
	
}