rule Mal_Mints_loader
{
meta:
	description = "Identifies mints loader malware"
strings: 
    $str1 = "=mints21"
	$str2 = "User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.5129"

condition:
  any of them
	
}

