// flarestrings -n 16 sample_1 | sort | uniq > s1
// comm -12 s1 s2 | comm -12 - s3 | comm -12 - s4 > common

rule Sample_2 {
    meta:
        author = "0x1"
        description = "Detect stealer sample2"

    strings:
        $discord = "%appdata%\\discord\\Local Storage\\leveldb" ascii wide nocase
        $steam   = "Software\\Valve\\SteamLogin Data" ascii wide nocase
        $filez1  = "FileZilla\\recentservers.xml" ascii wide nocase
        $filez2  = "FileZilla\\sitemanager.xml" ascii wide nocase

    condition:
        all of them
}
