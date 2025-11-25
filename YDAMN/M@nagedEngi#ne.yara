rule Mal_Manage_Engine_RAT
{
meta:
	description = "Identifies Managed Engine RAT malware"
strings: 
    $str1 = "ManageEngine"
	$str2 = "UEMS_Agent"
	$str4 = "dcagentservice.exe"
	$domain1 = "zl-12366.oss-cn-hongkong.aliyuncs.com"

condition:
  any of them
	
}

