rule Mal_Vidar
{
meta:
	description = "Identifies Vidar malware"
strings: 
    $str1 = "https://t.me/"
	$str2 = "steamcommunity.com"
	$str3 = "Microsoft\\Edge Dev\\User Data"
	$str4 = "Microsoft\\Edge SXS\\User Data"
	$str5 = "Microsoft\\Edge Beta\\User Data"
	$str6 = "Torch\\User Data"
	$c2_1 = "195.201.121.47"
	$c2_2 = "5.75.211.218"
	$c2_3 = "159.69.100.165"
	$c2_4 = "167.235.143.166"
	$c2_5 = "49.13.94.153"
	$c2_6 = "116.203.167.169"
	$c2_7 = "206.188.196.37"
condition:
  3 of them
	
}
