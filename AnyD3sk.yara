rule Mal_Any_Desk_RAT
{
meta:
	description = "Identifies Any_Desk RAT malware"
strings: 
	$str1 = "AnyDesk.exe"

condition:
  any of them
	
}	