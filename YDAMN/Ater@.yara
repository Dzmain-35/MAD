rule Mal_Atera_Agent
{
meta:
	author = "Dmain"
	description = "Identifies Atera Agent malware"
strings: 
	$str1 = "AteraAgent.exe"
	$str2 = "PubNub.dll"
	$str3 = "54.175.191.205"
	
	
condition:
	  any of them
}

