# Rapport — Exercice 1 : « Never Too Late, Mister »

**TP Forensic Mémoire — Master CDSI M1**  
**Étudiant :** [Votre nom]  
**Date :** 2026-04-26  
**Dump analysé :** `exercice1.raw`

---

## Q1 — Intégrité du dump & profil système

**Commande :**
```bash
sha256sum /mnt/c/Users/hp5/Downloads/TP-Forensic-CDSI-M1/dumps/exercice1.raw
VOL_IMAGE=cincan/volatility3 ../scripts/vol.sh -f /data/exercice1.raw windows.info
```

**Sortie :**
```
88e708413898c98351d1a5a221799fc34460dfecb20e482ca5247b0b113b8cf2  exercice1.raw

Volatility 3 Framework 1.0.0-beta.1

Variable                            Value
Kernel Base                         0xf8000261f000
DTB                                 0x187000
Symbols                             file:///symbols/windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz
primary                             0 WindowsIntel32e
memory_layer                        1 FileLayer
KdDebuggerDataBlock                 0xf800028100a0
NTBuildLab                          7601.17514.amd64fre.win7sp1_rtm.
CSDVersion                          1
KdVersionBlock                      0xf80002810068
Major/Minor                         15.7601
MachineType                         34404
KeNumberProcessors                  1
SystemTime                          2019-12-11 14:38:00
NtSystemRoot                        C:\Windows
NtProductType                       NtProductWinNt
NtMajorVersion                      6
NtMinorVersion                      1
PE MajorOperatingSystemVersion      6
PE MinorOperatingSystemVersion      1
PE Machine                          34404
PE TimeDateStamp                    Sat Nov 20 09:30:02 2010
```

**Interprétation & réponse :**  
Le dump `exercice1.raw` présente l'empreinte SHA-256 :  
`88e708413898c98351d1a5a221799fc34460dfecb20e482ca5247b0b113b8cf2`

- **Système d'exploitation :** Windows 7 SP1 (NtMajorVersion 6, NtMinorVersion 1, build 7601.17514.amd64fre.win7sp1_rtm)
- **Architecture :** AMD64 — 64 bits (MachineType 34404)
- **Date et heure d'acquisition :** 2019-12-11 à 14:38:00 UTC
- **Nombre de processeurs :** 1
- **Racine système :** `C:\Windows`
- **Outil d'acquisition :** DumpIt

---

## Q2 — Comptes utilisateurs locaux & session active

**Commandes :**
```bash
# 1. Lister les comptes locaux via la base de registre SAM (Volatility 3)
VOL_IMAGE=cincan/volatility3 ../scripts/vol.sh -f /data/exercice1.raw windows.registry.printkey --key "SAM\Domains\Account\Users\Names"

# 2. Identifier les sessions interactives et le propriétaire du dump (Volatility 2)
../scripts/vol.sh -f /data/exercice1.raw --profile=Win7SP1x64 getsids | grep -iE "explorer|DumpIt"
```

**Sortie :**
```
# Sortie de la ruche SAM :
[...]
2019-12-10 10:17:14.000000      0xf8a0014e9010  Key     CMI-CreateHive{...}\SAM\Domains\Account\Users\Names        Administrator
2019-12-10 10:17:14.000000      0xf8a0014e9010  Key     CMI-CreateHive{...}\SAM\Domains\Account\Users\Names        Alissa Simpson
2019-12-10 10:17:14.000000      0xf8a0014e9010  Key     CMI-CreateHive{...}\SAM\Domains\Account\Users\Names        Guest
2019-12-10 10:17:14.000000      0xf8a0014e9010  Key     CMI-CreateHive{...}\SAM\Domains\Account\Users\Names        HomeGroupUser$
2019-12-10 10:17:14.000000      0xf8a0014e9010  Key     CMI-CreateHive{...}\SAM\Domains\Account\Users\Names        SmartNet

# Sortie de getsids :
explorer.exe (604): S-1-5-21-...-1001 (SmartNet)
explorer.exe (2504): S-1-5-21-...-1003 (Alissa Simpson)
DumpIt.exe (796): S-1-5-21-...-1001 (SmartNet)
```

**Interprétation & réponse :**  
La base de registre SAM indique la présence de plusieurs comptes utilisateurs locaux : `Administrator`, `Alissa Simpson`, `Guest`, `HomeGroupUser$` et `SmartNet`.

L'analyse des processus via leurs identifiants de sécurité (SID) montre qu'il y a deux instances du processus `explorer.exe` en cours d'exécution, indiquant deux sessions interactives ouvertes simultanément :
- Une session pour **SmartNet** (PID 604, RID 1001)
- Une session pour **Alissa Simpson** (PID 2504, RID 1003)

La session interactive principale au moment du dump appartient à l'utilisateur **SmartNet**, car c'est sous ce compte qu'a été exécuté l'outil d'acquisition mémoire `DumpIt.exe` (PID 796).

---

## Q3 — Sessions interactives simultanées

**Commande :**
```bash
VOL_IMAGE=cincan/volatility3 ../scripts/vol.sh -f /data/exercice1.raw windows.pslist
```

**Sortie (extraits pertinents) :**
```
PID     PPID    ImageFileName   SessionId  CreateTime
...
# Processus de la session 1 (SmartNet)
604     2016    explorer.exe    1          2019-12-11 14:32:25.000000
1984    604     cmd.exe         1          2019-12-11 14:34:54.000000
2424    604     mspaint.exe     1          2019-12-11 14:35:14.000000
796     604     DumpIt.exe      1          2019-12-11 14:37:54.000000

# Processus de la session 2 (Alissa Simpson)
2504    3000    explorer.exe    2          2019-12-11 14:37:14.000000
1512    2504    WinRAR.exe      2          2019-12-11 14:37:23.000000
```

**Interprétation & réponse :**  
L'analyse de la liste des processus (`windows.pslist`) révèle les applications exécutées au sein de chaque session :

1. **Session 1 (Utilisateur principal : SmartNet)**
   - L'utilisateur a une invite de commande ouverte (`cmd.exe` PID 1984).
   - L'application au premier plan (outre l'outil d'acquisition `DumpIt.exe` PID 796) est **Microsoft Paint** (`mspaint.exe` PID 2424).

2. **Session 2 (Utilisateur en arrière-plan : Alissa Simpson)**
   - L'utilisateur a ouvert l'application **WinRAR** (`WinRAR.exe` PID 1512), ce qui indique la manipulation d'une archive compressée.

---

## Q4 — Historique terminal & fichiers manipulés

**Commande :**
```bash
../scripts/vol.sh -f /data/exercice1.raw --profile=Win7SP1x64 consoles
```

**Sortie (extraits) :**
```
ConsoleProcess: conhost.exe Pid: 2692
[...]
Cmd #0 at 0x1de3c0: St4G3$1
----
Screen 0x1e0f70 X:80 Y:300
Dump:
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\SmartNet>St4G3$1
ZmxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0=
Press any key to continue . . .
```

**Interprétation & réponse :**  
Dans le terminal `cmd.exe` (PID 1984), l'utilisateur **SmartNet** a saisi la ligne de commande exacte suivante :
`St4G3$1`

Cela a provoqué l'exécution d'un fichier nommé **`St4G3$1`** situé dans le répertoire de travail actuel (`C:\Users\SmartNet>`). L'exécution de ce fichier a affiché en sortie la chaîne de caractères encodée en Base64 : `ZmxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0=`.

*(Note : L'autre console active montre l'exécution de l'outil d'acquisition mémoire DumpIt).*

---

## Q5 — Fichier compressé protégé

**Commandes :**
```bash
# 1. Localiser le fichier en mémoire
../scripts/vol.sh -f /data/exercice1.raw --profile=Win7SP1x64 filescan | grep -i "Important.rar"

# 2. Extraire le fichier
../scripts/vol.sh -f /data/exercice1.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fa3ebc0 --dump-dir=/data/extractions

# 3. Vérifier la taille et l'empreinte
ls -lh extractions/
sha256sum extractions/*
```

**Sortie :**
```
0x000000003fa3ebc0      1      0 R--r-- \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar

DataSectionObject 0x3fa3ebc0   None   \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar

-rwxrwxrwx 1 root root 44K Apr 27 10:54 file.None.0xfffffa8001034450.dat
6ddeb36999d7233a4e4f0e3002ae729e01263da7a50ad3b4b4492e317cc257e9  extractions/file.None.0xfffffa8001034450.dat
```

**Interprétation & réponse :**  
Le fichier compressé protégé est nommé **`Important.rar`**. Il est situé dans le répertoire `C:\Users\Alissa Simpson\Documents\`.

Son extraction depuis la mémoire a produit le fichier `file.None.0xfffffa8001034450.dat`.  
La taille du fichier compressé est de **44 Ko** (44 Kilooctets).  
*(Empreinte SHA-256 : `6ddeb36999d7233a4e4f0e3002ae729e01263da7a50ad3b4b4492e317cc257e9`)*

---

## Q6 — Récupération du mot de passe du fichier compressé

**Commandes :**
```bash
# 1. Tenter l'extraction pour lire le commentaire de l'archive (avec 7z ou unrar)
unrar e extractions/file.None.0xfffffa8001034450.dat

# 2. Récupérer le hash NTLM d'Alissa Simpson
../scripts/vol.sh -f /data/exercice1.raw --profile=Win7SP1x64 hashdump
```

**Sortie (extraits) :**
```
# Sortie de unrar :
Archive comment:
Password is NTLM hash(in uppercase) of Alissa's account passwd.

# Sortie de hashdump :
Alissa Simpson:1003:aad3b435b51404eeaad3b435b51404ee:f4ff64c8baac57d22f22edc681055ba6:::
```

**Interprétation & réponse :**  
La tentative d'extraction de l'archive RAR a révélé un commentaire intégré : *"Password is NTLM hash(in uppercase) of Alissa's account passwd."*

La démarche complète a donc été :
1. Lire le commentaire de l'archive qui nous donne la condition.
2. Utiliser le plugin `hashdump` pour extraire la base SAM de la mémoire et obtenir le hash NTLM de l'utilisateur **Alissa Simpson**.
3. Le hash extrait est `f4ff64c8baac57d22f22edc681055ba6`.
4. Converti en majuscules comme demandé, le secret d'ouverture de l'archive est : **`F4FF64C8BAAC57D22F22EDC681055BA6`**.

---

## Q7 — Première moitié du flag

**Commande :**
```bash
[À COMPLÉTER]
```

**Sortie :**
```
[À COMPLÉTER]
```

**Réponse :**  
`flag{[À COMPLÉTER]`

---

## Q8 — Seconde moitié du flag (artefact graphique)

**Commande :**
```bash
[À COMPLÉTER]
```

**Sortie :**
```
[À COMPLÉTER]
```

**Réponse :**  
`[À COMPLÉTER]}`

---

## Q9 — Flag complet & chronologie des actions

**Flag complet :**  
`flag{[À COMPLÉTER]}`

**Chronologie :**

| Horodatage | Action | Artefact |
|------------|--------|----------|
| [À compléter] | [À compléter] | [À compléter] |

---

## Annexe — Toutes les commandes utilisées

```bash
# 1. Intégrité du dump
sha256sum /mnt/c/Users/hp5/Downloads/TP-Forensic-CDSI-M1/dumps/exercice1.raw

# 2. Profil système
VOL_IMAGE=cincan/volatility3 ../scripts/vol.sh -f /data/exercice1.raw windows.info

# [Ajouter toutes les commandes suivantes au fur et à mesure]
```
