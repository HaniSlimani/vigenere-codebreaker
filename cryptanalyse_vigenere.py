# Sorbonne Université 3I024 2024-2025
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant 1 : SLIMANI 21321846
# Etudiante 2 : AKKA 28715199

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [0.09213, 0.01035, 0.03018, 0.03754, 0.17175, 0.01094, 0.01062, 0.01072,
           0.07507, 0.00383, 0.00007, 0.06137, 0.02650, 0.07031, 0.04914, 0.02370,
           0.01016, 0.06609, 0.07817, 0.07374, 0.06356, 0.01645, 0.00001, 0.00407,
           0.00230, 0.00123]
# Chiffrement César
def chiffre_cesar(txt, key):
    """
    decale chaque lettre du txt de key positions
    style césar, les autre caracteres restent pareil
    """
    resultat = []  # list pr stocker lettres decalee

    for lettre in txt:
        pos = alphabet.find(lettre)  # trouver position dans alphabet
        if pos != -1:
            # decalage modulo 26 pr rester ds alphabet
            nouvelle_pos = (pos + key) % 26
            resultat.append(alphabet[nouvelle_pos])
        else:
            resultat.append(lettre)  # autre char on laisse comme ca
    
    return "".join(resultat)  # transforme liste en chaine
# Dechiffrement Cesar
def dechiffre_cesar(txt, key):
    """
    dechiffre txt en inversant césar
    juste rappel chiffre_cesar avec -key
    """
    return chiffre_cesar(txt, -key)

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    decale chaque lettre de txt selon la cle key
    si la cle est plus courte que txt elle boucle
    """
    resultat = []  # liste pour stocker lettres decalee
    n = len(key)

    for i in range(len(txt)):
        pos = alphabet.find(txt[i])
        if pos != -1:
            # i % n pr faire repeter la cle
            nouvelle_pos = (pos + key[i % n]) % 26
            resultat.append(alphabet[nouvelle_pos])
        else:
            resultat.append(txt[i])  # autre char on laisse comme ca

    return "".join(resultat)  # transforme liste en chaine

# -------------------------------------------------
# Dechiffrement Vigenere
# -------------------------------------------------
def dechiffre_vigenere(txt, key):
    """
    dechiffre txt avec cle key
    on soustrait le decalage au lieu d'ajouter
    """
    resultat = []
    n = len(key)

    for i in range(len(txt)):
        pos = alphabet.find(txt[i])
        if pos != -1:
            nouvelle_pos = (pos - key[i % n]) % 26
            resultat.append(alphabet[nouvelle_pos])
        else:
            resultat.append(txt[i])  # autre char reste pareil

    return "".join(resultat)

# -------------------------------------------------
# Analyse de frequences
# -------------------------------------------------
def freq(txt):
    """
    compte combien de fois chaque lettre apparait
    retourne un tableau d'entiers, indice = position lettre
    """
    hist = [0] * len(alphabet)  # initialise un tableau de 0 pr chaque lettre

    for lettre in txt:
        pos = alphabet.find(lettre)  # cherche la position ds alphabet
        if pos != -1:
            hist[pos] += 1  # on incremente le compteur de cette lettre

    return hist  # renvoie le tableau d'occurences
# -------------------------------------------------
# Lettre la plus frequente
# -------------------------------------------------
def lettre_freq_max(txt):
    """
    trouve la lettre qui apparait le plus dans txt
    renvoie son indice dans l'alphabet
    si plusieurs lettres ont meme freq, prend la premiere
    """
    hist = freq(txt)  # utilise freq() pr compter chaque lettre

    # index() renvoie la position du premier max, donc egalite gerée
    return hist.index(max(hist))

# Indice de coincidence
def indice_coincidence(hist):
    """
    calcule IC a partir du tableau hist
    formule: somme(ni*(ni-1)) / (n*(n-1))
    ni = occurences de chaque lettre
    n = total de lettres
    """
    n = sum(hist)
    if n <= 1:
        return 0.0  # evite division par 0
    numerateur = sum(ni * (ni - 1) for ni in hist)
    return numerateur / (n * (n - 1))

# Recherche la longueur de la clef
def longueur_clef(cipher):
    """
    teste toutes les longueurs de clef de 1 a 20
    decoupe le texte en colonnes et calcule IC
    si moyenne IC > 0.06 on renvoie la longueur
    """
    for k in range(1, 21):
        indice_colonne = []
        for j in range(k):
            # colonne j: prendre une lettre sur k a partir de j
            colonne = cipher[j::k]
            indice_colonne.append(indice_coincidence(freq(colonne)))
        if sum(indice_colonne) / len(indice_colonne) > 0.06:
            return k
    return -1  # si aucune longueur valide
    


# Table des decalages pour chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    calcule la clef probable a partir du texte chiffre
    on parcourt chaque colonne correspondant a chaque lettre de la clef
    on suppose que la lettre la plus frequente de la colonne = E
    decalage = indice_lettre_max - 4 (mod 26)
    """
    decalages = [0] * key_length

    for i in range(key_length):
        # colonne i: prendre une lettre sur key_length a partir de i
        colonne = cipher[i::key_length]
        # indice de la lettre la plus frequente
        indice_max = lettre_freq_max(colonne)
        # decalage par rapport a E (indice 4)
        decalages[i] = (indice_max - 4) % 26

    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    :cipher: str (texte chiffré avec Vigenère)
    -> str (texte clair supposé)
    
    Cette fonction fait une première tentative de cryptanalyse.  
    Elle commence par estimer la longueur probable de la clé grâce à l'indice de coïncidence.  
    Puis elle regarde chaque colonne du texte chiffré et suppose que la lettre la plus fréquente 
    correspond au 'E', ce qui permet de déduire le décalage de chaque colonne.  
    Enfin, elle applique le déchiffrement Vigenère avec la clé retrouvée.

    Limites et résultats :
    - Cette méthode fonctionne surtout sur des textes longs, où les fréquences de lettres sont représentatives.
    - Sur des textes courts ou atypiques, elle échoue souvent.
    - Dans notre test 5 (100 textes), seulement 18 textes ont été correctement déchiffrés.
      Cela montre que l’hypothèse "lettre la plus fréquente = E" n’est pas toujours fiable.
    """
    # on trouve la longueur de la cle
    key_length = longueur_clef(cipher)

    # on recupere les decalages
    decalages = clef_par_decalages(cipher, key_length)

    # on dechiffre avec vigenere
    return dechiffre_vigenere(cipher, decalages)


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec decalage
def indice_coincidence_mutuelle(h1, h2, d):
    """
    calcule l'indice de coincidence mutuelle entre deux textes
    h1 = frequence lettres texte 1
    h2 = frequence lettres texte 2
    d = decalage a tester sur texte 2
    on decale h2 de d positions et on multiplie les occurences correspondantes
    renvoie un nombre entre 0 et 1 indiquant la similarité
    utile pour trouver le decalage relatif entre colonnes
    """
    n1 = sum(h1)
    n2 = sum(h2)
    
    resultat = 0.0
    for i in range(26):
        j = (i + d) % 26
        resultat += h1[i] * h2[j]
    
    return resultat / (n1 * n2)

# Renvoie le tableau des decalages probables
def tableau_decalages_ICM(cipher, key_length):
    """
    calcule le decalage de chaque colonne par rapport a la premiere
    cipher = texte chiffre
    key_length = longueur de la cle
    premiere colonne = reference (decalage 0)
    pour chaque autre colonne on teste tous les decalages 0-25
    et on garde celui qui maximise l'indice de coincidence mutuelle
    renvoie la liste des decalages pour toutes les colonnes
    """
    decalages = [0] * key_length
    
    col0 = cipher[0::key_length]
    h0 = freq(col0)
    
    for i in range(1, key_length):
        colonne = cipher[i::key_length]
        h = freq(colonne)
        
        meilleur_icm = -1
        meilleur_d = 0
        
        for d in range(26):
            icm = indice_coincidence_mutuelle(h0, h, d)
            if icm > meilleur_icm:
                meilleur_icm = icm
                meilleur_d = d
        
        decalages[i] = meilleur_d
    
    return decalages
# Cryptanalyse V2 avec ICM
def cryptanalyse_v2(cipher):
    """
    on deduit la longueur de la cle avec l'indice de coincidence
    puis on calcule les decalages relatifs de chaque colonne par rapport a la premiere
    colonne avec l'ICM. on aligne toutes les colonnes sur la premiere.
    le texte obtenu est comme un texte chiffre avec cesar, donc on le dechiffre
    en trouvant la lettre la plus frequente.

    cette methode marche mieux que v1 car elle est plus robuste sur des textes courts
    mais elle peut encore echouer si le texte est trop court car les frequences
    ne representent pas bien le francais.
    resultats du test 7 : la plupart des textes longs passent, certains courts echouent
    """
    # trouver la longueur de la cle
    key_length = longueur_clef(cipher)

    # calculer les decalages relatifs par rapport a la premiere colonne
    decalages = tableau_decalages_ICM(cipher, key_length)

    # aligner toutes les colonnes sur la premiere
    txt_aligne = dechiffre_vigenere(cipher, decalages)

    # trouver le decalage de Cesar en cherchant la lettre la plus frequente
    cle_cesar = (lettre_freq_max(txt_aligne) - 4) % 26

    # dechiffrer le texte
    return dechiffre_cesar(txt_aligne, cle_cesar)

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de meme taille et
# calcule la correlation lineaire de Pearson
def correlation(L1, L2):
    """
    calcule le coeff de correlation de Pearson entre deux listes L1 et L2
    indique a quel point elles sont corrlees
    valeur proche de 1 = tres corrlees positivement
    """
    n = len(L1)
    m1 = sum(L1) / n   # moyenne de L1
    m2 = sum(L2) / n   # moyenne de L2

    numerateur = 0.0
    denom1 = 0.0
    denom2 = 0.0

    for i in range(n):
        numerateur += (L1[i] - m1) * (L2[i] - m2)
        denom1 += (L1[i] - m1) ** 2
        denom2 += (L2[i] - m2) ** 2

    # retourne la correlation entre L1 et L2, arrondie a 10 decimales
    return round(numerateur / (math.sqrt(denom1) * math.sqrt(denom2)), 10)

def clef_correlations(cipher, key_length):
    """
    cherche les decalages de chaque colonne qui maximisent la correlation avec freq_FR
    retourne la moyenne des correlations max et la cle estimee
    chaque colonne est comme un texte chiffre avec César, on garde le decalage qui colle le mieux aux frequences francaises
    """

    key = [0] * key_length   # tableau pour stocker la cle estimee
    score = 0.0              # somme des meilleures correlations pour calculer la moyenne

    for i in range(key_length):
        colonne = cipher[i::key_length]  # extraire les lettres de la colonne i
        h = freq(colonne)                # compter les occurences des lettres
        n = sum(h)                       # nombre total de lettres dans la colonne

        meilleure_corr = float("-inf")   # initialisation de la meilleure correlation
        meilleur_d = 0                   # decalage correspondant

        for d in range(26):              # tester tous les decalages possibles
            profil = [h[(j + d) % 26] / n for j in range(26)]  # profil normalisé pour ce decalage
            c = correlation(profil, freq_FR)                   # calculer correlation avec freq_FR
            if c > meilleure_corr:       # si c’est mieux que precedent
                meilleure_corr = c       # on garde la meilleure correlation
                meilleur_d = d           # et le decalage correspondant

        key[i] = meilleur_d               # stocker le decalage pour cette colonne
        score += meilleure_corr           # ajouter la meilleure correlation pour la moyenne

    score /= key_length                   # calculer la moyenne sur toutes les colonnes
    return (score, key)                   # renvoyer la moyenne et la cle estimee
# Cryptanalyse V3 avec correlations
# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    effectue une cryptanalyse avancée du texte chiffre avec vigenere
    elle teste toutes les longueurs de cle possibles et choisit celle
    qui maximise la correlation moyenne avec les frequences francaises
    pour ensuite dechiffrer le texte

    la methode est tres robuste : 94 textes sur 100 sont correctement dechiffres
    les textes echouant sont tres courts et les frequences par colonne ne sont pas representatives
    """
    # initialisation du meilleur score et de la cle correspondante
    meilleur_score = float("-inf")
    meilleure_cle = [0]

    # on teste toutes les longueurs de cle possibles
    for key_length in range(1, 21):
        # cle et score moyen pour cette longueur de cle
        score, key = clef_correlations(cipher, key_length)

        # on garde la cle qui donne le score moyen le plus eleve
        if score > meilleur_score:
            meilleur_score = score
            meilleure_cle = key

    # dechiffrement du texte avec la cle retenue
    # chaque colonne est decalee selon la cle estimee
    return dechiffre_vigenere(cipher, meilleure_cle)

################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
