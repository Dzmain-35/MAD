rule Mal_PrivateLogger
{
meta:
	description = "Identifies Plogger malware"
strings: 
    $star = "***********************************************************"
	$pr1 = /.+Best.+\n.+\n.+Private.+\n.+\*/

condition:
  all of them
	
}

rule Mal_PrivateLogger_V2
{
meta:
	description = "Identifies Plogger malware"
strings: 
    $pr1 = "Private"
	$bt1 = "Best"
	$str1 = "user data" nocase
	$str2 = "Clipboard.txt"
	

condition:
  $pr1 and $bt1 and 2 of ($str*)
	
}

