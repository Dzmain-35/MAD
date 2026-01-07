rule Mal_Action1_RMM
{
meta:
	description = "Identifies Action1 malware"
strings: 
	$str1 = "action1_remote_exe"
	$str2 = "a1_sas_dll_file"
 	$str4 = "action1_agent.exe"
	$str5 = "www.action1.com"
	$str6 = "Action1 Agent"

condition:
  any of them
	
}

