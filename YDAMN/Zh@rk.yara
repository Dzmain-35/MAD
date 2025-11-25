rule Mal_ZharkBot
{
meta:
	description = "Identifies Zharkbot malware"
strings: 
    $str1 = "OpiumG4ng"
	$str2 = "Couldnt open url!"
	$domain1 = "testedsnakeoptic.com"
	$domain2 = "leveledoperationalcert.com"
	$domain3 = "solutionhub.cc:443/socket"

condition:
  any of them
	
}

