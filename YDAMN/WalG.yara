rule Mal_Waltuhium_Grabber
{
meta:
	description = "Identifies WaltuhiumGrabber malware"
strings: 
    $name = "Waltuhium Grabber"
	$str2 = "StealCommonFiles"
	$str3 = "Coded by Waltuh"
	$str4 = "https://t.me/waltuhium"
	
condition:
  $name and 1 of ($str*)
	
}

