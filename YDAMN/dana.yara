rule Mal_DanaBot
{
meta:
	description = "Identifies Danabot malware"
strings: 
    $name = "MutCStealer"
	$str2 = "MutCAddZipFile"
	$str3 = "MutCInjectionProcessm"
	$str4 = "LedxKBWF4MiM3x9F7zmCdaxnnu8A8SUohZ"
	$str5 = "0xb49a8bad358c0adb639f43c035b8c06777487dd7"
	$str6 = "MutCFileGrabber"
	$str7 = "set-brand-Diners"
	$str8 = "TY4iNhGut31cMbE3M6TU5CoCXvFJ5nP59i"
	$str9 = "12eTGpL8EqYowAfw7DdqmeiZ87R922wt5L"

condition:
  $name and 1 of ($str*)
	
}

