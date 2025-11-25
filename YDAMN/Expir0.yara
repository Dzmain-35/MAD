rule Mal_Expiro
{
meta:
	description = "Identifies Expiro malware"
strings: 
    $str1 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36 MicroMessenger/6.5.2.501 NetType/WIFI WindowsWechat QBCore/3.43.884.400 QQBrowser/9.0.2524.400"
	$str2 = ".biz"
	$domain1 = "82.112.184.197"
	$domain2 = "przvgke.biz"

condition:
  2 of them
	
}

