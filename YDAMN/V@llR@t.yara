rule Mal_ValleyRAT
{
meta:
	description = "Identifies ValleyRAT malware"
strings: 
    $str1 = "18.166.193.8"
	$str2 = "Microsoft Mail Update Task MachineCore"
	$domain1 = "Windows Mail\\install.cfg"
	$domain2 = "ParphaCrashReport64.exe"
	$domain3 = "ParphaCrashReport64.exe"

condition:
  2 of them
	
}

