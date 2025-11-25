rule Mal_MetaStealer
{
meta:
	description = "Identifies MetaStealer malware"
strings:
	$str1 = "ssqsmisuowqcwsqo.xyz"
	$str2 = "rat\\client\\stealer" ascii wide
    $str3 = "IBrowserBase@stealer" 
    $str4 = "ChromeBrowser@stealer"
   	$str5 = "EdgeBrowser@stealer"
   	$str6 = "FirefoxBrowser@stealer"
    $str7 = "stealertest.dll"
	$str8 = "89.191.234.14"
	$str9 = "C:\\130823\\notbotnet\\client\\stealer" ascii wide
	$str10 = "ywcuqkkmmqioiwqk.xyz"
	$str11 = "api/client_hello"
condition:
  any of them

}