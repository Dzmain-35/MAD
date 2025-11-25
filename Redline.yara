rule Mal_Redline
{
meta:
	description = "Identifies Redline malware"
strings: 
	$str1 = "%userprofile%\\Desktop|*.txt,*.doc*,*key*,*wallet*,*seed*|0"
	$str2 = "Chrome\\User Data\\AutofillStates\\*"
	$str3 = "tempuri.org"
	$str4 = "net.tcp://"
	$c2_2 = "37.1.203.45"
	$c2_1 = "45.135.232.2"
	$c2_3 = "5.42.64.70"
	$c2_4 = "185.29.9.108"
	$c2_5 = "147.45.45.81"
	$c2_6 = "94.232.249.204"
	
condition:
  2 of them
	
}