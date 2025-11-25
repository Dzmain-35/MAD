rule Mal_RustyStealer
{
    meta:
        description = "Identifies Rust Stealer malware"

    strings:
        $str1 = "C:\\Users\\Trabalho\\.rustup\\toolchains"
        $str2 = "C:\\Users\\Trabalho\\.cargo\\registry\\src\\index.crates.io-"
        $str3 = "handshake.rs"
        $str4 = "mutex.rs"

    condition:
        3 of ($str*)
}