rule Mal_Syncro_RAT
{
meta:
	description = "Identifies Syncro RMM malware"
strings: 
	$domain1 = "syncromsp.com"
	$domain2 = "myworkmarco.syncroapi.com"
	$str1 = "Syncro.App.Runn"
	$str2 = "syncromsp"

condition:
  any of them
	
}

rule Mal_Splashtop
{
meta:
	description = "Identifies Syncro RMM malware"
strings: 
	$domain1 = /.+relay\.splashtop\.com/
	$str1 = "api.splashtop.com"
	$str2 = "Splashtop Inc. Self CA"
	$str3 = "Splashtop Remote"

condition:
  any of them
	
}

