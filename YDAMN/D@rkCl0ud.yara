rule Mal_Dark_Cloud
{
meta:
	description = "Identifies Dark Cloud malware"
strings: 
    $name = "DARKCLOUD"
	$str1 = "DCS V3.2"
	$str3 = "\\360Chrome\\Chrome\\User Data"
    $str4 = "\\Comodo\\Dragon\\User Data"
    $str5 = "\\MapleStudio\\ChromePlus\\User Data"
    $str6 = "\\Iridium\\User Data"
    $str7 = "\\7Star\\7Star\\User Data" 

condition:
  $name and 1 of ($str*)
	
}

