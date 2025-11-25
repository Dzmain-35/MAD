import "pe"


rule Mal_Pure_RAT
{
meta:
	description = "Identifies PureLog Stealer malware"
strings:
        // Wallet extension IDs
        $id_tronlink = "ibnejdfjmmkpcnlpebklmnkoeoihofec"
        $id_metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn"
        $id_binance = "fhbohimaelbohpjbbldcngcnapndodjp"
        $id_yoroi = "ffnbelfdoeiohenkjibnmadjiehjhajb"
        $id_jaxx = "cjelfplplebdjjenllpjcblmjkfcffne"
        $id_bitapp = "fihkakfobkmkjojpchpfgcmhfjnmnfpi"
        $id_iwallet = "kncchdigobghenbbaddojjnnaogfppfj"
        $id_terra = "aiifbnbfobpmeekipheeijimdpnlpgpp"
        $id_bitclip = "ijmpgkjfkbfhoebgogflfebnmejmfbml"
        $id_equal = "blnieiiffboillknjnepogjhkgnoapac"
        $id_wombat = "amkmjjmmflddogmhpjloimipbofnfjih"
        $id_nifty = "jbdaocneiiinmjbjlgalhcelgbejmnid"

        // Wallet names
        $wallet_tronlink = "TronLink"
        $wallet_metamask = "MetaMask"
        $wallet_binance = "Binance Chain Wallet"
        $wallet_yoroi = "Yoroi"
        $wallet_jaxx = "Jaxx Liberty"
        $wallet_bitapp = "BitApp Wallet"
        $wallet_iwallet = "iWallet"
        $wallet_terra = "Terra Station"
        $wallet_bitclip = "BitClip"
        $wallet_equal = "EQUAL Wallet"
        $wallet_wombat = "Wombat"
        $wallet_nifty = "Nifty Wallet"
	
condition:
  3 of them
	
}



rule PureLogs_Stealer_core {
    meta:
        author = "RussianPanda"
        description = "Detects Pure Logs Stealer Core Payload"
        date = "12/26/2023"

    strings:
        $s1 = {7E 58 00 00 0A [15] 28 20 00 00 0A 18 6F 0A 02 00 0A 0B}
        $s2 = {50 6C 67 43 6F 72 65}
        $s3 = {7E 64 01 00 0A 28 65 01 00 0A}

    condition:
        all of ($s*) and filesize < 5MB
        and pe.imports("mscoree.dll")
		
}


rule purelogs_stealer_initial_dropper {
	meta:
	        author = "RussianPanda"
	        decription = "Detects PureLogs Stealer Initial Payload"
	        reference = "https://russianpanda.com/2023/12/26/Pure-Logs-Stealer-Malware-Analysis/"
	        date = "1/10/2024"

	strings:
	        $s1 = {73 ?? 00 00 06 28 ?? 00 00 ?? 2A}
	        $s2 = {28 ?? 00 00 06 74 ?? 00 00 1B 28 ?? 00 00 0A 2A}
	        $s3 = {28 ?? 00 00 ?? 75 ?? 00 00 01 72 ?? 00 00 70 6F ?? 00 00 0A 2A}
	        $s4 = {28 ?? 00 00 ?? 75 ?? 00 00 01 72 ?? 00 00 ?? 20 00 01 00 00 14 14 14 6F ?? 00 00 ?? 26}
	        $s5 = {28 ?? 00 00 ?? 73 ?? 00 00 [29] 73 15 00 00 0A [22] 28 01 00 00 2B 28 02 00 00 2B}
       
 	condition:
		all of ($s*)
        	and uint16(0) == 0x5A4D and filesize < 1MB
		
}

rule Mal_Purelogs_Stealer_PureHVNC
{
    meta:
        description = "Detects Purelogs Stealer based on repeated PureHVNC string"

    strings:
        $purehvnc = "PureHVNC"
		$ip1 = "216.250.248.68"

    condition:
        #purehvnc >= 5 or $ip1
}

