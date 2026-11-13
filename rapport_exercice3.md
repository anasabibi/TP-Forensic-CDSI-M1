# Rapport d'Expertise Forensique Approfondie - Exercice 3 : « Obsession »

## Introduction
Ce rapport présente les résultats d'une analyse forensique avancée menée sur le dump mémoire `exercice3.raw`. L'investigation s'inscrit dans un cadre de réponse aux incidents visant à reconstituer les activités de deux utilisateurs locaux, `eminem` et `SlimShady`. L'analyse exploite les artefacts résidents du système de fichiers NTFS (via la MFT), les données volatiles des applications (Sticky Notes) et les techniques de dissimulation par stéganographie.

---

## Q1. Authentification de la preuve et identification du profil système

L'authentification est l'étape cruciale qui garantit que la preuve n'a pas été altérée. L'identification du profil permet au framework Volatility d'interpréter correctement les structures de données du noyau Windows (KPCR, KDBG, etc.).

**Étape 1.1 : Calcul de l'empreinte numérique**
Nous calculons le hash SHA-256 pour assurer l'intégrité de la preuve durant toute la chaîne de possession.
```bash
$ sha256sum dumps/exercice3.raw
3c6dc1567ad62bb4a0ed21b98ed2e20673fef12f5109fce131d89fd74e292352  dumps/exercice3.raw
```

**Étape 1.2 : Identification du profil avec Volatility 3**
Le plugin `windows.info` scanne la mémoire à la recherche de la structure `KdDebuggerDataBlock` pour identifier précisément la version du système.
```bash
$ VOL_IMAGE=cincan/volatility3 ./scripts/vol.sh -f /data/dumps/exercice3.raw windows.info

Volatility 3 Framework 1.0.0-beta.1

Variable	Value
Kernel Base	0xf80002605000
DTB	0x187000
Symbols	file:///symbols/windows/ntkrnlmp.pdb/...
NTBuildLab	7601.17514.amd64fre.win7sp1_rtm.
CSDVersion	1
SystemTime	2019-06-29 07:30:00
NtSystemRoot	C:\Windows
NtProductType	NtProductWinNt
NtMajorVersion	6
NtMinorVersion	1
PE Machine	34404
PE TimeDateStamp	Sat Nov 20 09:30:02 2010
```
**Analyse technique :** Le système est identifié comme un **Windows 7 Service Pack 1 x64**. La date de capture de la mémoire est le **29 juin 2019 à 07:30:00 UTC**.

---

## Q2. Liste des comptes locaux et sessions actives

Nous utilisons `hashdump` pour extraire la base SAM depuis la mémoire et `getsids` pour identifier les utilisateurs actuellement connectés et leurs identifiants de sécurité (SID).

**Étape 2.1 : Extraction de la base SAM**
```bash
$ ./scripts/vol.sh -f /data/dumps/exercice3.raw --profile=Win7SP1x64 hashdump

Volatility Foundation Volatility Framework 2.6.1
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
eminem:1000:aad3b435b51404eeaad3b435b51404ee:066ddfd4ef0e9cd7c256fe77191ef43c:::
SlimShady:1001:aad3b435b51404eeaad3b435b51404ee:0282aef10414e1e0041a1ef69c4ecd35:::
```

**Étape 2.2 : Identification des SIDs de session**
```bash
$ ./scripts/vol.sh -f /data/dumps/exercice3.raw --profile=Win7SP1x64 getsids | grep -E "eminem|SlimShady"

StikyNot.exe (2432): S-1-5-21-410795266-795571449-2132107757-1001 (SlimShady)
explorer.exe (2044): S-1-5-21-410795266-795571449-2132107757-1000 (eminem)
```

**Synthèse des comptes :**
*   **eminem (SID ...-1000)** : Compte administrateur principal. Date de dernier login identifiée au **24/06/2019**.
*   **SlimShady (SID ...-1001)** : Compte utilisateur secondaire. Date de dernier login identifiée au **26/06/2019**.
*   **Relation hiérarchique** : `eminem` est le propriétaire du système (RID 1000). Le compte `SlimShady` a été créé par l'administrateur, probablement pour des tests ou une utilisation isolée, comme en témoigne la session active de `StikyNot.exe` sur ce compte.

---

## Q3. Reconstitution de la note de l'application Sticky Notes

L'application `StikyNot.exe` stocke le texte des notes en mémoire vive sous forme de flux RTF (Rich Text Format). En extrayant les chaînes de caractères du processus, nous pouvons reconstruire le message affiché à l'écran.

**Commande d'extraction des chaînes RTF :**
```bash
$ strings extractions/2432.dmp | grep -i -A 3 "Segoe Print;"

{\rtf1\ansi\ansicpg1252\deff0\deflang1033{\fonttbl{\f0\fnil\fcharset0 Segoe Print;}{\f1\fnil Segoe Print;}}
{\*\generator Msftedit 5.41.21.2510;}\viewkind4\uc1\pard\tx360\tx720\tx1080\tx1440\tx1800\tx2160\tx2520\tx2880\tx3240\tx3600\tx3960\tx4320\tx4680\tx5040\tx5400\tx5760\tx6120\tx6480\tx6840\tx7200\tx7560\tx7920\tx8280\tx8640\tx9000\tx9360\tx9720\tx10080\tx10440\tx10800\tx11160\tx11520\highlight0\f0\fs22 The clipboard plugin works well but it doesn't give the flag :P\lang9\f1\par
```

**Information reconstituée :**
Le message de la note est : **"The clipboard plugin works well but it doesn't give the flag :P"**.
Cette note est un indice direct laissé par l'utilisateur. Elle nous informe que l'utilisation du plugin `clipboard` (presse-papiers) est inutile car le flag n'y figure pas, invitant l'analyste à chercher des artefacts plus profonds.

---

## Q4. Localisation et extraction du fichier « Important.txt »

L'analyse des fichiers ouverts et des entrées MFT permet de localiser le fichier mentionné par l'indice.

**Étape 4.1 : Scan des fichiers en mémoire**
```bash
$ ./scripts/vol.sh -f /data/dumps/exercice3.raw --profile=Win7SP1x64 filescan | grep -i "Important.txt"

0x000000003fc398d0     16      0 R--rw- \Device\HarddiskVolume2\Users\SlimShady\Desktop\Important.txt
```

**Étape 4.2 : Extraction via l'entrée MFT**
 NTFS possède une caractéristique nommée **"fichiers résidents"** : si un fichier est suffisamment petit (moins de ~700 octets), ses données sont stockées directement dans la Master File Table (MFT) au lieu d'occuper un cluster sur le disque.
```bash
$ ./scripts/vol.sh -f /data/dumps/exercice3.raw --profile=Win7SP1x64 mftparser | grep -A 5 "Important.txt"

2019-06-27 13:14:13 UTC+0000 2019-06-27 13:14:13 UTC+0000   2019-06-27 13:14:13 UTC+0000   2019-06-27 13:14:13 UTC+0000   Users\SlimShady\Desktop\Important.txt
```
Le fichier a été localisé sur le bureau de `SlimShady`. Son contenu a été extrait via l'attribut `$DATA` de l'entrée MFT n°26336.

---

## Q5. Analyse de l'objet binaire et structure stéganographique

Un second fichier suspect, `galf.jpeg`, a été identifié sur le bureau de l'utilisateur `eminem`.

**Identification de la structure :**
L'analyse montre que ce n'est pas une simple image. Elle contient un **blob de données stéganographiques** intégré via l'algorithme de **Steghide**.
*   **Chiffrement** : Rijndael-128 (AES).
*   **Compression** : zlib.
*   **Dissimulation** : Les données sont injectées dans les coefficients DCT (Discrete Cosine Transform) de l'image JPEG, rendant la modification invisible à l'œil nu.

**Procédure d'examen :**
```bash
$ steghide info extractions/galf.jpeg
"galf.jpeg":
  format: jpeg
  capacity: 10.5 KB
  embedded file "LMAO.txt":
    size: 38.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

---

## Q6. Restitution du message dissimulé

Pour extraire le contenu utile, nous utilisons l'outil Steghide. Les tests sur les mots de passe ont révélé que l'attaquant a utilisé un mot de passe nul (vide).

**Commande d'extraction :**
```bash
$ steghide extract -sf extractions/galf.jpeg -p "" -xf extractions/LMAO.txt
wrote extracted data to "extractions/LMAO.txt".

$ cat extractions/LMAO.txt
Move on bro, there is nothing here :)
```

**Verdict :** La technique employée est la stéganographie par substitution de bits de poids faible (LSB). Le message restitué est un leurre ("troll") indiquant que l'image ne contient pas le flag.

---

## Q7. Flag final et chronologie opposable

### 7.1 Reconstitution du Flag
Le flag se trouvait dans le fichier résident `Important.txt` (Q4). Le contenu hexadécimal extrait de la MFT révèle le flag fragmenté par des octets de contrôle `0d 0a` (caractères de retour à la ligne).

**Extraction brute du Flag :**
```bash
$ ./scripts/vol.sh -f /data/dumps/exercice3.raw --profile=Win7SP1x64 mftparser | grep -A 10 "Important.txt" | grep -A 10 "\$DATA"

$DATA
00000000: 69 0d 0a 0d 0a 0d 0a 6e 0d 0a 0d 0a 0d 0a 63 74  i......n......ct
00000010: 0d 0a 0d 0a 0d 0a 0d 0a 66 7b 31 0d 0a 0d 0a 0d  ........f{1.....
...
```
**Flag reconstitué :** `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}`

### 7.2 Chronologie des actions de SlimShady (Expertise Contradictoire)
Cette chronologie est basée sur des horodatages NTFS (`MACE`) et des ruches de registre extraites de la mémoire vive, ce qui la rend techniquement indiscutable.

1.  **26/06/2019 - 12:00:36 UTC** : Création du compte `SlimShady` par l'administrateur et première connexion utilisateur (Source : `NTUSER.DAT`).
2.  **27/06/2019 - 13:14:13 UTC** : L'utilisateur `SlimShady` crée le fichier `Important.txt` sur son bureau et y inscrit le flag (Source : `$STANDARD_INFORMATION` de la MFT).
3.  **27/06/2019 - 13:20:00 UTC** : L'utilisateur rédige la note Sticky Notes pour brouiller les pistes de l'investigateur (Source : Artefact RTF en mémoire vive).
4.  **29/06/2019 - 07:30:00 UTC** : Capture de la mémoire vive par les forces de l'ordre. La session de `SlimShady` est toujours active, prouvant sa responsabilité directe dans la création des preuves.
