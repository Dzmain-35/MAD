rule Mal_Lampion
{
meta:
	description = "Identifies Lampion malware"
strings:
	$str2 = "inde-faturas.com"
	$str3 = "3.144.21.25"
	$str4 = "moduloEXE"
	$str5 = "103.117.141.126"
	$str6 = "142.250.217.164"

condition:
  any of them
	
}


rule MAL_Lampion2
{
  meta:
    description = "Detects startup .cmd/.bat"

  strings:
    $rundll32  = /start\s+\/min\s+rundll32\.exe/i ascii
    $wscript   = /start\s+\/min\s+wscript\.exe/i  ascii
    $dll_path  = /C:\\Users\\[^\\]+\\AppData\\Roaming\\[^"]+\.dll/i ascii
    $vbs_path  = /C:\\Users\\[^\\]+\\Desktop\\[^"]+\.vbs/i    ascii
    $echo_off  = /@echo\s+off/i ascii
    $if_exist  = /if\s+exist\s+"/i ascii

  condition:
    filesize < 10KB and
    $rundll32 and $wscript and
    ( $dll_path or $vbs_path ) and
    ( #echo_off + #if_exist ) >= 1
}
