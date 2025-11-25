rule Mal_PrivateLoader
{
meta:
	description = "Identifies PrivateLoader malware"
strings: 
	$str1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
	$ip1 = "178.128.15.164"
	$ip2 = "146.75.36.84"
condition:
  any of them
	
}	