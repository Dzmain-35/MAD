rule Mal_DanaBot
{
meta:
	description = "Identifies Danabot malware"
strings: 
    $name = "DanaBot"
	$str2 = "FROM Win32_NetworkAdapter"
	$str3 = "FROM moz_cookies"
	$str4 = "FROM `local_stored_cvc`"
	$str6 = "FROM Win32_OperatingSystem"
	$str7 = /DanaBot\_64.+\.pas/
	

condition:
  $name or 2 of ($str*)
	
}

