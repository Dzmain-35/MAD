rule Mal_ToiToin
{
meta:
	description = "Identifies ToiToin LATAM malware"
strings: 
	$str1 = "bdeunlock.exe"
	$str2 = "admin.ini"
	$str3 = "IDC1.temp"
	$c21 = "20.13.152.128"
condition:
  2 of them
	
}



