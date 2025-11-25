rule Mal_Ousaban
{
meta:
	description = "Identifies Ousaban malware"
strings: 
	$str1 = "agloader.dll" nocase
	$str2 = "WebUI.dll"
	$str3 = "postUP.php"
condition:
  any of them
	
}



