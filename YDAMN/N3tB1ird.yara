import "pe"

rule Mal_NetBird_RAT
{
    meta:
        description = "Identifies N3tBird RAT malware"
    strings:
        $str1 = "netbird.io"
        $str2 = "netbird.cloud"
		$str3 = "sweethome.netbird.cloud"
		$ip1 = "192.3.95.152"
    condition:
        any of them
}

