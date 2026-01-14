rule Mal_Phantom_Stealer
{
meta:
	description = "Identifies PhantomStealer Malware"
strings: 
    $str1 = "Phantom stealer"
	$str2 = "https://t.me/Oldphantomoftheopera"
	$str3 = "www.phantomsoftwares.site"
	$domain1 = "taikei-rmc-co.biz"
	$ip1 = "103.253.42.215"

condition:
  any of them
	
}

