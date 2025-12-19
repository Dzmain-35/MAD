rule Mal_Isabella_Wine_RAT
{
meta:
	description = "Identifies Isabella Wine RAT"
strings: 
  $str1 = "IsabellaWine"
	$str2 = "steamcommunity.com"
	$str3 = "keylog.txt"
	$domain1 = "lolvcvllovcle.com"


condition:
  3 of them
	
}

