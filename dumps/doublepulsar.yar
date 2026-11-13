rule doublepulsar {
    strings:
        $s1 = { 51 52 53 56 57 55 }
    condition:
        $s1
}
