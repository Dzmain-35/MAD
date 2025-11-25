rule Mal_Nanocore
{
meta:
	description = "Identifies Nanocore malware"
strings:
        $client = "NanoCore Client"
        $exe = "NanoCore Client.exe"
        $plugin = "NanoCore.ClientPlugin"
        $host = "NanoCore.ClientPluginHost"
		$c2 = "elroithegodofnsppd.ddnsfree.com"

condition:
  any of them
	
}

