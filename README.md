# TP Forensic Mémoire — Master CDSI M1

Ce dépôt regroupe les travaux pratiques, scripts d'analyse et rapports d'investigation numérique (Forensic Mémoire) réalisés dans le cadre du **Master 1 CDSI** (Cyber Défense et Sécurité de l'Information).

---

## 🎯 Objectifs du TP

- Analyse forensique de dumps mémoire Windows (Windows 7 SP1, Windows XP SP3).
- Détection d'injections de code, de malwares et de mécanismes de persistance.
- Utilisation approfondie des frameworks **Volatility 2** et **Volatility 3** (via conteneur Docker).
- Recherche de signatures avec **YARA**, extraction d'artefacts et stéganographie.

---

## 📁 Structure du projet

| Fichier / Dossier | Description |
| :--- | :--- |
| **[rapport_exercice1.md](file:///c:/Users/hp5/Downloads/TP-Forensic-CDSI-M1/rapport_exercice1.md)** | Rapport d'investigation — Exercice 1 (*Win7 SP1 x64*) |
| **[rapport_exercice3.md](file:///c:/Users/hp5/Downloads/TP-Forensic-CDSI-M1/rapport_exercice3.md)** | Rapport d'investigation — Exercice 3 (*Win7 SP1 x64*) |
| **[rapport_exercice4.md](file:///c:/Users/hp5/Downloads/TP-Forensic-CDSI-M1/rapport_exercice4.md)** | Rapport d'investigation — Exercice 4 (*Win XP SP3*) |
| **[rapport_exercice5.md](file:///c:/Users/hp5/Downloads/TP-Forensic-CDSI-M1/rapport_exercice5.md)** | Rapport d'investigation — Exercice 5 |
| **`scripts/`** | Wrappers Docker Volatility (`vol.ps1`, `vol.sh`) et scripts d'analyse (`find_smb.py`) |
| **`extractions/`** | Artefacts, captures d'écran et fichiers extraits pendant l'analyse |
| **`POLY-ETUDIANT.pdf`** | Énoncés et mémo de référence du TP |

> **Note :** Les dumps mémoire volumineux (`*.raw` et `*.dmp`, totalisant ~4 Go) sont exclus du suivi Git via `.gitignore` conformément aux limites de taille imposées par GitHub.

---

## 🛠️ Technologies & Outils

- **Volatility 2 & 3** (`cincan/volatility`)
- **Docker**
- **Python 3**
- **YARA**
- **Steghide / Foremost**
