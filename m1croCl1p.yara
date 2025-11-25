rule Mal_MicroClip
{
meta:
	description = "Identifies MicroClip malware"
strings: 
	$str1 = "FomsTudio.exe"
	$str2 = "ix.servebbs.com"
	$str3 = "DTCommonRes.dll"
	
condition:
  any of them
	
}



