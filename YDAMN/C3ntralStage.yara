rule Mal_Centra_Stage_RMM
{
meta:
	description = "Identifies CentraStage RMM malware"
strings: 
    $str1 = "CentraStage" nocase
	$str2 = "CentraStage.Cag" nocase
	$str3 = "CagService.exe" nocase
	$domain2 = "vidal-monitoring.centrastage.net"

condition:
  any of them
	
}

