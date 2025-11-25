rule Mal_Ph0enix_Clipper
{
meta:
	description = "Identifies Ph0enix_Clipper/Clip Banker malware"
strings: 
    $str1 = "Phoenix_Clipper"
	$str2 = "TrojanAIbot.exe"
	$str3 = "Phoenix-Rat-Clipper"

	
condition:
  any of them
	
}

