rule Mal_Gooxi0n
{
meta:
	description = "Identifies Gooxi0n malware"
strings: 
	$str1 = "pobus64.exe" nocase
	$str2 = "poda32"
	$str3 = "assisths.exe"
	$str4 = "assists.exe"
	$name1 = "Gooxion"
	$name2 = "@gooxion.com"
	$str5 = "69.176.89.135"
condition:
  1 of ($name*) or 2 of ($str*)
	
}



