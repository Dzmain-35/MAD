
rule Mal_Rhadamanthys_Stealer
{
    meta:
        family      = "Rhadamanthys"
        author      = "Dmain"
        date        = "2025-09-11"
        purpose     = "High-confidence hit on Rhadamanthys payload/config"

    strings:
        $d1 = "purepower2.kozow.com" ascii wide
        $ip = "45.88.186.160" ascii
        $mm = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii   // MetaMask
        $cw = "egjidjbpglichdcondbcbdnbeeppgdph" ascii   // Coinbase Wallet
        $tw = "hmeobnfnfcmdkdcmlblgagmfpfboieaf" ascii   // Trust Wallet
        $xz = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii   // XDEFI
        $rn = "fnjhmkhhmkbjkkabndcnnogagogbneec" ascii   // Ronin
        $bz = "ffnbelfdoeiohenkjibnmadjiehjhajb" ascii   // Binance
        $p1 = "\\User Data\\" ascii nocase
        $p2 = "Google\\Chrome\\User Data\\" ascii
        $p3 = "Microsoft\\Edge\\User Data\\" ascii

    condition:
        4 of them
}
