# Guide de collaboration — BookTopia

Ce document décrit la procédure recommandée pour installer, modifier, tester et livrer BookTopia en binôme. Il ne contient aucun secret.

## 1. Récupérer le projet

```powershell
git clone https://github.com/Aybskt/BookTopia.git
Set-Location BookTopia
```

Structure utile :

```text
BookTopia/
├── src/                         application et racine web locale
├── storage/                     configuration locale non versionnée
├── docs/                        rapports et guides
└── assets/                      captures utilisées par GitHub
```

Ne copiez pas de fichier `config.json`, de CSV de production, de cache ou de mot de passe dans Git, un ZIP ou une messagerie.

## 2. Préparer l’environnement local

Pré-requis :

- PHP 8.0 ou supérieur ;
- extensions cURL, JSON, mbstring et GD ;
- Git ;
- accès en écriture au dossier `storage/`.

Créez la configuration locale :

```powershell
Copy-Item storage/config.example.json storage/config.json
```

Complétez uniquement les clés nécessaires dans `storage/config.json`. Les valeurs vides sont acceptées pour les services optionnels disposant d’un fallback.

| Clé | Usage | Obligatoire |
|---|---|---:|
| `key_api` | Google Books | Recommandée |
| `unsplash_key` | Hero quotidien | Non |
| `nasa_key` | NASA APOD, page Tech | Non |
| `ipinfo_token` | Localisation, page Tech | Non |
| `ip2location_key` | Localisation de secours | Non |

Lancez ensuite :

```powershell
php -S localhost:8000 -t src
```

Ouvrez [http://localhost:8000](http://localhost:8000).

## 3. Travailler avec Git

Synchronisez `main` avant chaque tâche :

```powershell
git switch main
git pull --ff-only
git switch -c feature/nom-court
```

Règles recommandées :

- une branche par correction ou fonctionnalité ;
- des commits courts et explicites en français ;
- aucun fichier généré ou secret ajouté de force ;
- une relecture du diff avant push ;
- une Pull Request pour intégrer une modification importante.

Avant de committer :

```powershell
git status --short
git diff --check
```

Exemple de message :

```text
Corrige les couvertures de la page auteur
```

## 4. Contrôler la modification

### Syntaxe PHP

Sous PowerShell :

```powershell
$files = rg --files src -g '*.php' | Where-Object { $_ -notlike 'src\jpgraph\*' }
foreach ($file in $files) { php -l $file }
```

### Scénarios manuels essentiels

1. Charger l’accueil deux fois et vérifier l’absence de warning.
2. Rechercher un livre par titre puis par auteur.
3. Parcourir les cinq pages sans perdre la requête ou le thème.
4. Ouvrir une fiche et vérifier couverture, auteur et similaires.
5. Ouvrir une biographie et vérifier portrait, français et livres.
6. Ajouter puis supprimer un favori dans la bibliothèque.
7. Tester les thèmes clair et sombre sur mobile.
8. Vérifier que les pages de statistiques retournent une image valide.

### Contrôle des secrets

Avant chaque push, vérifiez que seules les valeurs d’exemple sont suivies :

```powershell
git status --short
git ls-files storage
```

Le résultat attendu pour `storage` est uniquement `storage/config.example.json`.

## 5. Conventions du projet

- Conserver les noms et signatures des fonctions existantes.
- Réutiliser `api_get_json()` pour tout appel JSON externe.
- Passer toute donnée distante affichée dans `e()`.
- Conserver les URLs internes existantes.
- Ajouter un placeholder pour toute image externe.
- Ne pas introduire de framework ou de dépendance Composer sans décision commune.
- Préserver les modifications non liées présentes dans l’arbre de travail.

## 6. Mettre en production sur InfinityFree

Le domaine est associé au dossier :

```text
booktopia.fr/htdocs/
```

Copiez **le contenu de `src/`**, pas le dossier `src` lui-même :

```text
booktopia.fr/htdocs/index.php
booktopia.fr/htdocs/include/
booktopia.fr/htdocs/images/
booktopia.fr/htdocs/.htaccess
```

Le stockage d’exécution doit se trouver dans :

```text
booktopia.fr/htdocs/.booktopia_storage/
```

Ce dossier doit contenir son `.htaccess` de protection, puis `config.json` et les fichiers de données nécessaires. Ne supprimez pas `.well-known/acme-challenge/` lorsqu’il est utilisé pour le certificat SSL.

Ordre de livraison conseillé :

1. sauvegarder la version distante ;
2. transférer les nouveaux fichiers applicatifs ;
3. ne pas écraser la configuration ni les CSV sans nécessité ;
4. vérifier `https://booktopia.fr` en navigation privée ;
5. tester recherche, détail, auteur et bibliothèque ;
6. contrôler le cadenas HTTPS et l’absence de contenu mixte ;
7. conserver la sauvegarde jusqu’à validation du binôme.

## 7. En cas de problème

| Symptôme | Vérification prioritaire |
|---|---|
| Erreur 403 | présence de `index.php`, droits et règles `.htaccess` |
| APIs indisponibles | clés, extension cURL, écriture du cache et quota fournisseur |
| Images absentes | HTTPS, CSP éventuelle, URL distante et placeholder |
| Statistiques vides | droits d’écriture sur `.booktopia_storage` et extension GD |
| Certificat non actif | DNS, installation du certificat et délai de propagation |
| Différence local/production | version PHP, extensions, chemins et cache ancien |

## 8. Handover

Lorsqu’un membre termine une tâche, il transmet :

- le lien de la Pull Request ou le hash du commit ;
- les pages affectées ;
- les scénarios testés ;
- les éventuelles limites connues ;
- les opérations de déploiement particulières, sans jamais transmettre les secrets dans le dépôt.
