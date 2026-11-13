import subprocess

passwords = [
    "",
    "clipboard",
    "plugin",
    "flag",
    "SlimShady",
    "eminem",
    "The clipboard plugin works well but it doesn't give the flag :P",
    "The clipboard plugin",
    "clipboard plugin"
]

for p in passwords:
    safe_p = "".join(x for x in p if x.isalnum())[:10]
    cmd = ['steghide', 'extract', '-sf', 'extractions/galf.jpeg', '-p', p, '-xf', f'extractions/steg_{safe_p}.txt', '-f']
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"Success with password: '{p}'")
    except Exception as e:
        pass
