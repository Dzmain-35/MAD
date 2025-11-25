rule Mal_Babylon_RAT
{
meta:
	description = "Identifies Babylon  malware"
strings: 
	$domain1 = "xtadts.ddns.net"
	$domain2 = "afxwd.ddns.net"
	$domain3 = "webdot.ddns.net"
	$domain4 = "andrefelipedonascime"
	$name1 = "BabylonRAT"
	$name2 = "ClassLibrary3.dll"


condition:
  2 of them
	
}

