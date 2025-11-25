rule Mal_0ptiTuneRAT
{
meta:
	description = "Identifies Bravura 0ptiTune malware"
strings: 
    $str1 = "manage.opti-tune.com"
	$str2 = "Bravura"
	$str3 = "OptiTune"
	$str4 = "leveledoperationalcert.com"
	$str5 = "OTService.exe"
	$str6 = "RealtimeAgent.exe"

condition:
  1 of them
	
}

