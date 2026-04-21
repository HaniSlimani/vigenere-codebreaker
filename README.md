# Vigenère Codebreaker

Cryptanalyse automatique du chiffre de Vigenère par analyse statistique.

Implémentation Python d'algorithmes classiques pour casser un chiffre de Vigenère sans connaître la clé : recherche de la longueur de clé par indice de coïncidence, puis déduction des décalages par corrélation fréquentielle.

## Fonctionnalités

- Chiffrement et déchiffrement César et Vigenère
- Analyse de fréquences des lettres
- Calcul de l'indice de coïncidence (IC)
- Détermination automatique de la longueur de clé (indice de coïncidence mutuel)
- Cryptanalyse en trois versions, de plus en plus robustes :
  - **V1** — analyse fréquentielle naïve par colonne
  - **V2** — utilisation de l'ICM pour déterminer les décalages relatifs
  - **V3** — corrélation avec la distribution du français de référence

## Structure

```
.
├── cryptanalyse_vigenere.py    # Module principal
├── germinal.txt                # Corpus de référence (français)
├── test-1-cesar.py             # Tests César
├── test-2-vigenere-cipher.py   # Tests chiffrement Vigenère
├── test-3-freq-IC.py           # Tests fréquences et IC
├── test-4-decalages.py         # Tests décalages
├── test-5-cryptanalyse-V1.py   # Cryptanalyse V1
├── test-6-ICM-decalages.py     # Tests ICM
├── test-7-cryptanalyse-V2.py   # Cryptanalyse V2
├── test-8-correlations.py      # Tests corrélations
├── test-9-cryptanalyse-V3.py   # Cryptanalyse V3
└── test-all.sh                 # Lance toute la batterie de tests
```

## Utilisation

Lancer la suite complète :

```bash
./test-all.sh
```

Ou un test spécifique :

```bash
python3 test-9-cryptanalyse-V3.py
```

## Méthode

L'approche repose sur deux outils statistiques :

**Indice de coïncidence** — mesure la probabilité que deux lettres tirées au hasard dans un texte soient identiques. Le français a un IC autour de 0,074 ; un texte aléatoire autour de 0,038. En découpant le chiffré en colonnes selon différentes longueurs de clé supposées, on trouve la bonne longueur quand l'IC moyen des colonnes est proche de celui du français.

**Indice de coïncidence mutuel (ICM)** — compare les distributions de fréquences entre deux textes avec un décalage. Permet de retrouver les décalages relatifs entre colonnes, puis le décalage absolu par rapport au français de référence.

## Dépendances

- Python 3
- Aucune bibliothèque externe

## Auteurs

- Hani Slimani
- [@akkaboutaina](https://github.com/akkaboutaina)
