rule Mal_BBtok
{
meta:
    description = "Identifies BBtok malware"
strings:
	$str1 = "Program Access and Computer Defaults" 
	$str2 = "ComputerDefaults.exe"	
condition:
  all of them
    
}
