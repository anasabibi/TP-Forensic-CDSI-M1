# Rapport Technique Forensique - Exercice 4 : « Vendredi noir »

## Introduction
Ce rapport détaille l'investigation numérique menée sur le dump mémoire `exercice4.raw`. L'analyse porte sur une infection par ransomware survenue le 12 mai 2017, une date historiquement marquée par l'émergence d'une cyberattaque mondiale sans précédent. L'objectif est de caractériser la menace, d'identifier les vecteurs de propagation et de proposer des mesures de remédiation.

---

## Q1. Authentification de la preuve et identification du profil système

### 1.1 Authentification du dump
La première étape consiste à garantir l'intégrité de la preuve numérique par le calcul d'une empreinte cryptographique.

**Commande exécutée :**
```bash
sha256sum dumps/exercice4.raw
```

**Sortie réelle :**
```text
76e8be1a3761878325fdff39a5ab1ff84922a0b18947e5268dd9175795ad2bf0  dumps/exercice4.raw
```

### 1.2 Identification du profil système
L'identification précise de l'OS est cruciale pour sélectionner les bons plugins Volatility et comprendre les vulnérabilités potentielles du poste.

**Commande exécutée :**
```bash
VOL_IMAGE=cincan/volatility3 ./scripts/vol.sh -f /data/dumps/exercice4.raw windows.info
```

**Sortie réelle (extraits) :**
```text
Variable	Value
Kernel Base	0x804d7000
DTB	0x39000
NTBuildLab	2600.xpsp_sp3_qfe.130704-0421
CSDVersion	3
Major/Minor	15.2600
SystemTime	2017-05-12 21:26:32
NtSystemRoot	C:\WINDOWS
NtMajorVersion	5
NtMinorVersion	1
```

**Analyse forensique :**
Le système est un **Windows XP Service Pack 3 (x86)**. La date de l'acquisition (12 mai 2017) est corrélée avec le déclenchement mondial de WannaCry. L'utilisation de Windows XP, un système qui n'était plus supporté officiellement par Microsoft depuis 2014, explique pourquoi cette machine était une cible privilégiée : elle ne disposait pas des correctifs de sécurité automatiques contre les vulnérabilités SMB récemment découvertes à l'époque.

---

## Q2. Analyse des processus et détection d'anomalies

L'analyse de la liste des processus permet de repérer des exécutables dont le nom, le chemin ou la hiérarchie parent-enfant sont suspects.

**Commande exécutée :**
```bash
VOL_IMAGE=cincan/volatility3 ./scripts/vol.sh -f /data/dumps/exercice4.raw windows.pslist
```

**Sortie réelle (extrait des lignes suspectes) :**
```text
PID	PPID	ImageFileName	CreateTime
1940	1636	tasksche.exe	2017-05-12 21:22:14.000000
740	1940	@WanaDecryptor@	2017-05-12 21:22:22.000000
```

**Analyse des suspicions :**
1.  **`tasksche.exe` (PID 1940)** : Bien que le nom ressemble à un composant système (Task Scheduler), son lancement sous le processus `explorer.exe` (PID 1636) est anormal pour un service système.
2.  **`@WanaDecryptor@` (PID 740)** : Ce processus est l'enfant de `tasksche.exe`. Le nom est une signature explicite du ransomware WannaCry. Sa présence confirme que la phase de chiffrement a été initiée et que l'interface de demande de rançon est active.

---

## Q3. Lignes de commande et chemins d'exécution

Pour confirmer la malveillance de `tasksche.exe`, nous examinons son chemin de lancement sur le disque.

**Commande exécutée :**
```bash
VOL_IMAGE=cincan/volatility3 ./scripts/vol.sh -f /data/dumps/exercice4.raw windows.cmdline
```

**Sortie réelle (extrait) :**
```text
PID	Process	Args
1940	tasksche.exe	"C:\Intel\ivecuqmanpnirkt615\tasksche.exe"
740	@WanaDecryptor@	@WanaDecryptor@.exe
```

**Interprétation forensique :**
Le binaire est exécuté depuis `C:\Intel\ivecuqmanpnirkt615\`. 
- **Le dossier `C:\Intel`** est un répertoire légitime, mais l'ajout d'un sous-dossier au nom aléatoire (`ivecuqmanpnirkt615`) est une technique de dissimulation. 
- **Deduction :** Le malware a utilisé un "dropper" pour se copier dans un répertoire jugé "neutre" par l'utilisateur, en prenant un nom de dossier difficile à identifier manuellement, assurant ainsi une forme de furtivité avant l'exécution du payload final.

---

## Q4. Analyse des mécanismes de persistance

Un malware cherche généralement à survivre à un redémarrage. Nous avons inspecté le registre et les services pour trouver des traces de persistance.

**4.1 Persistance par le Registre (Clé Run)**
La clé `Run` permet de lancer un programme automatiquement à chaque connexion d'utilisateur.

**Commande exécutée :**
```bash
VOL_IMAGE=cincan/volatility3 ./scripts/vol.sh -f /data/dumps/exercice4.raw windows.registry.printkey --offset 0xe1490b60 --key 'Microsoft\Windows\CurrentVersion\Run'
```

**Sortie réelle :**
```text
Last Write Time	Hive Offset	Type	Key	Name	Data	Volatile
2017-05-12 21:14:27	0xe1490b60	REG_SZ	...	ivecuqmanpnirkt615	"C:\Intel\ivecuqmanpnirkt615\tasksche.exe"	False
```

**4.2 Persistance par Service**
WannaCry installe également un service pour s'assurer une exécution avec des privilèges élevés au démarrage du système.

**Commande exécutée :**
```bash
VOL_IMAGE=cincan/volatility3 ./scripts/vol.sh -f /data/dumps/exercice4.raw windows.svcscan
```

**Sortie réelle (extrait) :**
```text
Offset	Order	Pid	State	Name	Display	Binary
0x675e48	115	N/A	SERVICE_STOPPED	mssecsvc2.0	Microsoft Security Center (2.0) Service	N/A
```
*Note : Bien que le service apparaisse arrêté dans ce dump (probablement car il a déjà fini sa propagation ou attend un redémarrage), son nom est un indicateur de compromission (IoC) universellement reconnu pour WannaCry.*

---

## Q5. Identification de la campagne d'attaque

Sur la base des artefacts techniques identifiés (processus, registre, service), nous concluons que la machine est victime du ransomware **WannaCry** (ou WanaCrypt0r).

**Preuves indépendantes :**
1.  **Indice 1 (Nom du binaire)** : Le processus `@WanaDecryptor@.exe` est le composant de déchiffrement graphique du ransomware.
2.  **Indice 2 (Service malveillant)** : Le nom du service `mssecsvc2.0` (Microsoft Security Center 2.0) est la signature de la composante "ver" de WannaCry.
3.  **Indice 3 (Comportement de dropper)** : Le déploiement dans un dossier aléatoire sous `C:\Intel` est une signature comportementale documentée du dropper de WannaCry.

---

## Q6. Mode de propagation et mécanisme de Kill Switch

### 6.1 Mode de propagation
WannaCry n'est pas un simple ransomware ; il possède une composante **ver (worm)** qui lui permet de se propager de manière autonome.
- **Vulnérabilité exploitée :** Il utilise l'exploit **EternalBlue** (identifié par la NSA et publié par le groupe Shadow Brokers). Cet exploit tire parti d'un dépassement de tampon dans le driver **srv.sys** du protocole **SMBv1** (port 445).

### 6.2 Le Kill Switch historique
L'attaque a été stoppée par la découverte d'un mécanisme d'arrêt d'urgence codé par les attaquants eux-mêmes.
- **Le domaine :** `www.iuqerfsodpifjposdfjhgosurijfaewrwergwea.com`
- **Mécanisme :** Le malware tente une requête HTTP vers ce domaine. Si le domaine **ne répond pas** (non enregistré), le malware procède au chiffrement. S'il répond (enregistré), le malware s'arrête. L'enregistrement de ce domaine par le chercheur Marcus Hutchins a activé ce "frein" au niveau mondial.

---

## Q7. Stratégie de chiffrement et types de fichiers visés

WannaCry ne chiffre pas l'intégralité du disque pour maintenir l'OS fonctionnel (afin que l'utilisateur puisse voir la demande de rançon).

**Extensions ciblées (Exemples) :** 
- Documents de travail : `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pdf`.
- Archives et bases de données : `.zip`, `.rar`, `.7z`, `.sql`, `.mdb`.
- Médias et photos : `.jpg`, `.jpeg`, `.png`, `.png`, `.tiff`.

**Stratégie :**
Le code malveillant parcourt les répertoires personnels de l'utilisateur (Bureau, Documents, etc.) et remplace les fichiers par une version chiffrée portant l'extension **`.WNCRY`**. Il utilise un algorithme de chiffrement asymétrique (RSA-2048) pour protéger les clés de chiffrement symétriques (AES-128) utilisées pour chaque fichier, rendant le déchiffrement impossible sans la clé privée détenue par les attaquants.

---

## Q8. Note d'incident à destination du RSSI

**Objet : Rapport de compromission majeur - Ransomware WannaCry**

**Résumé de l'incident :**
Une infection par ransomware de type ver a été identifiée sur le poste analysé. La compromission est totale pour les données utilisateur.

**Actions immédiates de confinement :**
1.  **Isolation physique :** Déconnecter immédiatement la machine du réseau filaire et Wi-Fi pour bloquer la propagation vers d'autres serveurs ou postes.
2.  **Blocage périmétrique :** Bloquer tout trafic sortant et entrant sur le port **TCP 445** (SMB) au niveau des commutateurs et pare-feu pour protéger les segments sains du parc.

**Actions de remédiation et récupération :**
1.  **Restauration :** Re-formater intégralement le poste et restaurer les fichiers à partir de sauvegardes hors-ligne antérieures au 12 mai 2017. **Ne jamais payer la rançon.**
2.  **Campagne de correctifs :** Déployer d'urgence le correctif de sécurité **MS17-010** sur l'intégralité du parc Windows encore en service.

**Leçons à tirer pour la sécurité du parc :**
- **Fin de vie logicielle :** Accélérer le remplacement ou l'isolation stricte des systèmes obsolètes (Windows XP/2003).
- **Désactivation SMBv1 :** Désactiver globalement le protocole SMBv1, jugé non sécurisé et obsolète.
- **Segmentation réseau :** Mettre en œuvre une segmentation réseau plus granulaire pour limiter les capacités de propagation latérale des vers informatiques.
