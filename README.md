# VRAM Guard

**Protège les zones défectueuses de la mémoire vidéo (VRAM) des cartes NVIDIA sous Windows.**
*Fences off defective VRAM regions on NVIDIA GPUs (Windows 10/11) so no other program can use them.*

Certaines cartes graphiques ont une petite zone de VRAM abîmée. Symptômes typiques :

- artefacts ou plantages dans les jeux, seulement quand la VRAM se remplit ;
- IA locale (Ollama, LM Studio, llama.cpp…) qui répond « 000000 », « ///// » ou du charabia ;
- erreurs CUDA aléatoires.

VRAM Guard teste la VRAM libre, puis **garde pour lui** les blocs défectueux : aucun jeu ni programme ne peut plus les recevoir. Ce n'est pas une réparation, c'est un contournement. Si la carte est sous garantie, faites-la échanger : le journal (bloc défectueux et nombre d'erreurs) peut servir de preuve.

## Téléchargement

Téléchargez `VRAM-Guard.exe` dans la page [Releases](../../releases). C'est un fichier unique, sans installation ni droits administrateur.

## Utilisation

1. Fermez les jeux et les programmes lourds, pour pouvoir tester toute la carte.
2. Lancez `VRAM-Guard.exe` et cliquez sur **Tester maintenant**.
   - « Aucune erreur » : votre VRAM libre est saine, inutile d'installer.
   - « N bloc(s) défectueux » : cliquez sur **Installer (protection permanente)**.
3. Une fois installé, il se lance tout seul à chaque ouverture de session, sans fenêtre, en priorité basse et à 0 % de processeur au repos.
   - Les blocs défectueux restent réservés en permanence.
   - Quand la carte est presque libre, il refait un test au plus toutes les 30 minutes.
4. Pour arrêter : relancez `VRAM-Guard.exe` et cliquez sur **Désinstaller**.

Ligne de commande :

| Commande | Effet |
|---|---|
| `VRAM-Guard.exe` | fenêtre : état, test, installation |
| `VRAM-Guard.exe --test` | test seul, résultat dans le journal |
| `VRAM-Guard.exe --background` | protection en arrière-plan (ce que lance le démarrage de Windows) |

Les fichiers sont dans `%LOCALAPPDATA%\VRAM-Guard` : la copie du programme, le journal `vram-guard.log` et l'état `etat.txt`. Le lancement automatique passe par un raccourci « VRAM Guard » dans le dossier Démarrage de Windows.

## Comment ça marche

- La VRAM libre est allouée par blocs de 64 Mo.
- Chaque bloc est rempli avec 4 motifs qui dépendent de l'adresse, puis relu **sur la carte graphique** (petits noyaux PTX). Chaque différence est comptée.
- Les blocs avec erreurs restent alloués ; les autres sont rendus immédiatement.
- Un bloc défectueux n'est **jamais** rendu. Certains défauts sont des effets d'alias : écrire *ailleurs* corrompt le bloc. Un bloc retesté seul peut donc paraître sain alors qu'il ne l'est pas.
- La VRAM réellement libre est lue avec NVML. Sous Windows (WDDM), `cuMemGetInfo` ignore les autres programmes.
- Plafond : 1 Gio réservé par carte. Plusieurs cartes NVIDIA sont gérées.
- Aucune dépendance : seulement le pilote NVIDIA (`nvcuda.dll`, `nvml.dll`).

## Limites

- **Cartes NVIDIA uniquement**, avec un pilote récent. Ne fonctionne pas sur AMD ni Intel.
- Il ne teste que la mémoire **libre** au moment du test : lancez le test avec la carte la plus vide possible.
- Si un jeu remplit **toute** la VRAM, Windows peut déplacer la mémoire réservée. Le test automatique suivant (carte presque libre) re-réserve la zone, mais entre-temps le défaut peut réapparaître. Baisser un peu la qualité des textures aide.
- Certains antivirus se méfient des programmes Python compilés avec PyInstaller (faux positif). Le code source complet est ici : vous pouvez le lire ou le recompiler.
- Testé sur une carte de génération Ampere (série RTX 30). Les autres générations n'ont pas encore été vérifiées : vos retours sont bienvenus dans les [Issues](../../issues).

## Compiler soi-même

Il faut Python 3.10 ou plus récent sous Windows. Le programme n'utilise que la bibliothèque standard (ctypes, tkinter).

```bat
python -m pip install pyinstaller
pyinstaller --onefile --noconsole --name VRAM-Guard vram_guard_app.py
```

L'exécutable est créé dans `dist\VRAM-Guard.exe`. Vous pouvez aussi lancer le script directement : `python vram_guard_app.py`.

## Licence

MIT : voir [LICENSE](LICENSE). Utilisation à vos risques. Le programme ne fait qu'allouer, écrire et relire de la mémoire vidéo libre, et ne modifie ni le pilote ni la carte.
