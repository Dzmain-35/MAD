rule Mal_Reply_Cloud_RAT
{
meta:
	description = "Identifies Reply Cloud RAT malware"
strings: 
    $str1 = "ReplyCloud"
	$str2 = "REPLY HOLDINGS INC"
	$str3 = "ReplyDesktopApp.exe"
	
condition:
  any of them
	
}

