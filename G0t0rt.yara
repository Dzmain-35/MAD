rule Mal_GoTO_RAT
{
meta:
	description = "Identifies GoTO RAT malware"
strings: 
	$str1 = "GoTo Resolve"
	$str2 = "GoToResolve"
	$c21 = "https://dumpster.console.gotoresolve.com/api/sendEventsV2"
	$c22 = "34.120.195.249"
	
condition:
  any of them
	
}


