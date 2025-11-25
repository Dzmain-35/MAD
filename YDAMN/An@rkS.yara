rule Mal_AnarchyStealer
{
meta:
	description = "Identifies Anarchy malware"
strings: 
	$str1 = "Anarchy Stealer"
	$str2 = "Stealerium"
	$str3 = "Sending Report  >> Started!"
	$str4 = "Anarchy Logs"
condition:
  2 of them
	
}
