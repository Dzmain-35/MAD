rule Mal_Nuclear_RAT
{
meta:
	description = "Identifies Nuclear RAT malware"
strings: 
	$str1 = "R.A.T Source 5 NUCLEAR RAT"
	$str3 = "Data\\Roaming\\GPret"
	$str2 = "Desktop\\Google Chrome.lnk"
	$str4 = "rdpwrap.in"
	$host1 = "5e:78:65:69:f9:9b:b0:a3:27:20:1a:76:d4:1c:f9:fa"
condition:
  any of them
	
}



