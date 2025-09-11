// strings sample_1

rule Sample_1 {
    meta:
        author = "0x1"
        description = "Detect ransomware sample1"

    strings:
        $torsite = "http://lockbitks2tvnmwk.onion/"
    
    condition:
        $torsite
}