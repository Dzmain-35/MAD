rule Mal_Muck_Stealer
{
meta:
	description = "Identifies Muck malware"
strings: 
    $str1 = "muck-stealer.py"
	$str2 = "muckautofill"
	$str3 = "muckpasswords"
	$str4 = "muckparsedcookies"
	$str5 = "muckcreditcards"
	$str6 = "Muck Stealer"

condition:
  any of them
	
}

