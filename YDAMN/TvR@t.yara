rule Mal_TVrat
{
meta:
	description = "Identifies SpyAgent/Tvrat malware"
strings: 
    $str1 = "_ASSISTANT\\04_Clients"
	$str2 = "assistant_spt.exe"
	$str3 = "Assistant system service"
	$str4 = "Teamviewer"
	$domain1 = "https://id.xn--80akicokc0aablc.xn--p1ai"

condition:
  2 of them
	
}

