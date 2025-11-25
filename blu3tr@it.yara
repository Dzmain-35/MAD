rule Mal_Bluetrait_RAT
{
meta:
	description = "Identifies BluetraitRAT malware"
strings: 
	$str1 = "bluetrait"
	$str2 = "level.exe"
	$str3 = "PAExec.exe"
	$str4 = "BluetraitUserAgent.exe"
	$str5 = "BluetraitAgent"
	$str6 = "Bluetrait MSP Agent.exe"
	$url1 = "revilox.bluetrait.io"
	$ip1 = "167.99.228.32"
condition:
  2 of them
	
}	