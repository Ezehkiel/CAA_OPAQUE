# CAA 2020

## Lab #2

#### Choix d'implémentation

##### Courbe elliptique

En ce qui concerne la courbe éliptique j'ai choisi de prendre la courbe `secp256r1`. En effet, en regardant le site https://www.keylength.com/fr/. J'ai choisi ce que recommandait l'ANSSI, c'est à dire 256bits. De plus, j'ai pensé que dans le cadre de ce laboratoire nous pouvions ne pas faire attention à la durée de vie des courbes, en production il serait peut-être plus "futurproof" de prendre la courbe de 384bits.

Le fait de choisir cette courbe m'a donc donné un paramètre τ d'une longueur de 128bit car |q| = 2τ

##### Authenc/AuthDec

Pour cette partie nous devions faire en sorte que ce soit "random-key robust". D'après ce qui est noté dans le draft du protocole cette propriété peut être remplie en faisant un `encrypt-the-mac` ou en modifiant GCM par exemple. Dans mon cas j'ai choisi d'utiliser `encrypt-then-mac` avec AES et HMAC256. 

Pour le mode de AES j'ai choisi CTR car, comme expliqué ici, https://web.cs.ucdavis.edu/~rogaway/papers/modes.pdf CTR est très efficace lorsque l'on veux simplement chiffrer les données, ce qui est notre cas.

-

-

##### Fonction de hashage H

Pour la fonction de hashage j'ai choisi d'utiliser BLAKE2b car d'après le cours c'est un algorithme qui est valide dans le futur. De plus, il semble plus rapide que MD5, SHA1, SHA2 et SHA3 et aussi sur que SHA3.

<img src="C:\Users\remi\AppData\Roaming\Typora\typora-user-images\image-20200522224912977.png" alt="image-20200522224912977" style="zoom: 67%;" />

Il a été possibe de définir la taille de l'output de la fonction. D'après la figure donnée la taille de sortie devait être de 2τ, ce qui nous fait une sortie de 256 bits.

##### PRF

Pour la PRF j'ai aussi choisi HMAC256 car, à nouveau, d'après l'ANSSI il est recommandé d'utiliser SHA-256 pour les fonctions de hashage et du coup le fait de choisir HMAC256 me permettait d'avoir SHA256 dans mon MAC.

#### Fonctionnementde OPAQUE



**Note:** nous sommes dans un corps additif cela veut dire que lorsque nous avons un exposant on faisons une multiplication et que lorsque nous avons une multiplication nous faisons une addition. Dans la description suivante nous avons adapté les formules au corps additif.

La première phase de OPAQUE est une phase d'enregistrement. On suppose que le client et le serveur communique à travers un canal sécurisé. Lors de cette phase il va se passer les choses suivante:

- Le serveur va tirer des nombres aléatoires (clés privées pour le client et le serveur et un nombre k pour le serveur) ainsi que des points sur une courbe elliptique (clés public du client et du serveur).

- Le serveur va calculer une clé **(rw)** qui a été généré à partir du password du client et du paramètre **k**.

- Il va ensuite utiliser **rw** pour chiffrer la clé privé du client, la clé public du client et la clé public du serveur.

- Puis une fois tout ces éléments calculés, il va les stocker dans un fichier/base de données avec comme identificateur l'id de l'utilisateur.

  En production cette phase doit se faire pour chaque utilisateur. Dans notre implémentation nous la faisons automatiquement étant donné que nous n'avons qu'un seul utilisateur

Par la suite nous avons la phase de login, c'est cette phase qui serait représenté par le loin sur une page web:

1. Client:
   - Le client va tirer aléatoirement deux nombre aléatoire dans $\mathbb{Z}_q$: **$r$, $x_u$**. Puis il va généré le point $X_u$ sur la courbe comme ceci: $X_u=g*{x_u}$ 
   - Puis il va calculer $\alpha$ comme ceci  $\alpha = (H'(password))^r$. Dans notre cas nous travaillons avec des courbes elliptique et il nous a été conseillé, dans un premier temps, d'utiliser $H'$ comme ceci: $H'(password) = g*{H(password)}$.

- 
- 