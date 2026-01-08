rule Mal_Gh0stRAT
{
meta:
	description = "Identifies Gh0stRAT malware"
strings: 
    $str1 = "WinSta0\\Default"
	$str2 = "GetClipboardData"
	$str3 = /(%)s\\shell\\open\\command/
	$ip1 = "129.226.170.223"
	$str4 = "ZhuDongFangYu.exe"
	$str5 = "Software\\Tencent\\Plugin\\VAS"
	$str6 = "UnThreat.exe" 
	$str7 = "LogonTrigger"
	$str8 = "AdjustTokenPrivileges"

condition:
  4 of them
	
}


rule Mal_Winos
{
meta:
	description = "Identifies Gh0stRAT variant Winos malware"
strings: 
    $str1 = "https://gitee.com/standar/plug-in-2/raw/master/QQGame.exe"
	$str2 = "https://ssl.xui.ptlogin2.weiyun.com"
	$str3 = /\|0:db\|0:lk\|0:hs\|0:ld\|0:ll\|0:hb\|0:pj\|3/
	$str4 = "timeout /t 60 /nobreak >nul"
	$ip1 = "localhost.ptlogin2.weiyun.com"
	$url1 = "https://y.qq.com/"

condition:
  2 of them
	
}
