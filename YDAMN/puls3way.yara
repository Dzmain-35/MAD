rule Mal_Pulseway
{
meta:
	description = "Identifies Pulseway RAT abused malware"
strings: 
  	$str1 = "Pulseway Client"
	$str2 = "PCMonitorSrv"
	$domain1 = "https://github.com/pulseway/LibreHardwareMonitor"
	$domain3 = "www.pulseway.com"
	$domain2 = "185.90.14.232"

condition:
  any of them
	
}
