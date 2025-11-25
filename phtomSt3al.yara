rule Mal_Phantom_Stealer
{
meta:
	description = "Identifies PhantomStealer Malware"
strings: 
    $str1 = "Phantom stealer"
	$str2 = "https://t.me/Oldphantomoftheopera"
	$str3 = "www.phantomsoftwares.site"

condition:
  any of them
	
}

