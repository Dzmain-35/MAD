rule Mal_Ninja_RMM
{
meta:
	description = "Identifies Ninja RMM malware"
strings: 
    $str1 = "NinjaOne-Agent"
	$str2 = "NinjaRMMAgentPatcher.exe"
	$domain1 = "NinjaRMMAgent.exe"


condition:
  any of them
	
}

