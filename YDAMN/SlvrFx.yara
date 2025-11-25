rule Mal_Silver_Fox
{
meta:
	description = "Identifies SilverFox malware"
strings: 
  	$str1 = "pythoncopy.exe" nocase
	$str2 = "pythoncan.exe"
	$str3 = "python_test.exe"
	$str4 = "Work7.zip" nocase
	$str5 = "nssm.exe"
	$str6 = "time.dll"
	$c21 = "8.210.99.24"
	$c22 = "mszjx0006.com"

condition:
  2 of them

}

