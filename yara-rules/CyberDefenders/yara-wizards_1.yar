import "math"
rule Yara_Wizards {
    meta:
        author = "0x1"
        description = "Detect Malware Sample"

    strings:
        $entrypoint = ".bat" ascii
        $cmdline = "cmd.exe /d /c bqwybceocy.bat"

        $script_part = /\.dat(\.\d+)?/

    condition:
        math.entropy(0, filesize) > 7 and
        any of ($entrypoint, $cmdline) and 
        #script_part > 3
}