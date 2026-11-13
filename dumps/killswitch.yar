rule killswitch {
    strings:
        $a = "iuqerf"
    condition:
        $a
}
