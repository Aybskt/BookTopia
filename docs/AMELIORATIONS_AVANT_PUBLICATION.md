# Audit de maturité et feuille de route — BookTopia

> État du projet au 18 août 2026
> Production : [booktopia.fr](https://booktopia.fr) · Dépôt : [Aybskt/BookTopia](https://github.com/Aybskt/BookTopia)

## Synthèse

BookTopia est désormais publiable pour une audience modérée. Les principaux défauts bloquants du prototype initial ont été corrigés : exposition des fichiers sensibles, erreurs API visibles, sélection bibliographique approximative, couvertures absentes, pagination vulnérable, incohérences graphiques et problèmes responsive.

Le prochain cycle doit privilégier la gestion des secrets, la confidentialité, les en-têtes HTTP et l’automatisation des tests. Ces sujets apportent davantage de valeur qu’une nouvelle refonte visuelle.

| Axe | État | Appréciation |
|---|---:|---|
| Fonctionnalités principales | ✅ Stable | Recherche, détails, auteurs, favoris et statistiques opérationnels |
| Design responsive | ✅ Stable | Direction artistique homogène sur mobile et bureau |
| Résilience des APIs | ✅ Stable | Cache, timeouts courts et fallbacks locaux |
| Sécurité applicative | 🟠 À renforcer | Bon socle, en-têtes et confidentialité à compléter |
| Tests automatisés | 🔴 À créer | Validation encore principalement manuelle |
| Documentation | ✅ À jour | Rapport, guide binôme et README alignés sur la version 2026 |

## Travail déjà réalisé

### Sécurité et exposition des fichiers

- [x] Bloquer l’indexation des dossiers avec `Options -Indexes`.
- [x] Refuser l’accès HTTP à `config.json`, `info.php` et aux fichiers CSV.
- [x] Exclure de Git les configurations réelles, caches, journaux et archives.
- [x] Isoler le stockage de production dans `.booktopia_storage/` protégé sur InfinityFree.
- [x] Échapper les données externes avec le helper `e()`.
- [x] Encoder les paramètres intégrés aux liens internes.
- [x] Valider les paramètres bornés tels que le type de recherche, l’index de page et le thème.
- [x] Utiliser `HttpOnly`, `SameSite=Lax` et `Secure` sous HTTPS pour le cookie de recherche.
- [x] Verrouiller les écritures concurrentes du compteur et des CSV avec `flock()`.

### APIs, performances et qualité des données

- [x] Remplacer les appels HTTP applicatifs par cURL.
- [x] Centraliser les réponses JSON dans `api_get_json()`.
- [x] Mettre chaque URL en cache pendant 900 secondes.
- [x] Utiliser un cache mémoire pendant une même requête PHP.
- [x] Appliquer des timeouts de connexion et de réponse courts.
- [x] Réutiliser une réponse périmée exploitable lorsqu’un fournisseur échoue.
- [x] Réduire les payloads Google Books avec `fields`, `projection=lite` et `printType=books`.
- [x] Préciser les correspondances avec `intitle:"…" inauthor:"…"`.
- [x] Utiliser les grandes couvertures OpenLibrary (`-L.jpg`).
- [x] Forcer les miniatures Google Books en HTTPS.
- [x] Ajouter des placeholders locaux pour livres et auteurs.
- [x] Prévoir des listes locales critiques sur l’accueil.
- [x] Renouveler le hero Unsplash une seule fois par jour avec fallback local.
- [x] Afficher les biographies Wikipédia en français ou fournir un repli francophone.
- [x] Filtrer et trier les dernières sorties sur leur date réelle.
- [x] Utiliser les données OpenLibrary pour tendances et popularité.

### Interface et cohérence

- [x] Refaire la direction artistique en vert profond et orange.
- [x] Moderniser le préchargeur et le favicon dans la même identité.
- [x] Créer une bibliothèque en forme d’étagères.
- [x] Uniformiser cartes, boutons, titres, espacements et états interactifs.
- [x] Limiter visuellement les titres longs dans les grilles.
- [x] Refaire la pagination et la limiter à cinq pages.
- [x] Empêcher le bouton « retour en haut » de masquer les actions de la page Tech.
- [x] Préserver le contexte pendant les changements de thème.
- [x] Refaire la page À propos avec un plan du site dynamique.
- [x] Harmoniser la page 404 avec l’identité du site.
- [x] Corriger les couvertures entre liste, détail et page auteur.
- [x] Rendre les graphiques JpGraph compatibles avec le déploiement actuel.
- [x] Adapter les écrans aux mobiles, tablettes et grands écrans.

### Livraison

- [x] Publier le site sur `https://booktopia.fr`.
- [x] Installer un certificat TLS.
- [x] Documenter la structure InfinityFree et le rôle de `htdocs`.
- [x] Publier un dépôt GitHub propre avec README, licence et captures.
- [x] Mettre à jour le rapport 2026 en HTML, ODT et PDF.

## Actions restantes

### P0 — Secrets et accès

#### 1. Renouveler les identifiants déjà transmis

Les clés API, mots de passe FTP et identifiants d’hébergement ayant été partagés dans une conversation ou une archive doivent être considérés comme compromis, même s’ils ne figurent pas dans Git.

- [ ] Régénérer les clés Google Books, Unsplash, NASA, IPinfo et IP2Location utilisées en production.
- [ ] Modifier les mots de passe FTP et des panneaux d’hébergement.
- [ ] Révoquer les anciennes valeurs après validation des nouvelles.
- [ ] Vérifier l’historique Git avec un scanner de secrets.
- [ ] Restreindre les clés par domaine, API ou quota lorsque le fournisseur le permet.

**Critère de validation :** aucun secret actif ne correspond à une valeur déjà communiquée et le site fonctionne avec les nouvelles clés.

### P1 — Confidentialité

#### 2. Réduire la collecte des adresses IP

`page-de-recherche.php` enregistre actuellement l’adresse IP avec certaines recherches. Cette donnée n’est pas nécessaire au classement des termes.

- [ ] Retirer la colonne IP ou anonymiser les deux derniers octets avant écriture.
- [ ] Définir une durée de conservation courte des CSV.
- [ ] Ajouter une purge périodique.
- [ ] Ajouter une page de confidentialité expliquant cookies, statistiques et fournisseurs tiers.

**Critère de validation :** aucune adresse IP complète n’est stockée et la politique publiée reflète exactement le comportement du code.

#### 3. Durcir les réponses HTTP

- [ ] Ajouter `X-Content-Type-Options: nosniff`.
- [ ] Ajouter une `Referrer-Policy` adaptée.
- [ ] Ajouter une `Permissions-Policy` minimale.
- [ ] Activer HSTS seulement après confirmation que tous les sous-domaines utiles supportent HTTPS.
- [ ] Déployer une CSP en mode rapport, corriger les violations, puis l’appliquer.
- [ ] Masquer la signature PHP si l’hébergeur l’autorise.

**Attention :** le projet utilise des images et APIs externes. Une CSP trop stricte peut masquer des couvertures ; tester chaque page avant activation.

#### 4. Protéger les opérations modifiant l’état

Les favoris sont actuellement pilotés côté client. Toute future mutation serveur devra être protégée dès son introduction.

- [ ] Documenter le modèle actuel de stockage des favoris.
- [ ] Ajouter des jetons CSRF si une suppression, importation ou sauvegarde passe côté serveur.
- [ ] Ajouter une limite de taille et une validation stricte lors d’un éventuel import de bibliothèque.

### P1 — Assurance qualité

#### 5. Ajouter des tests automatisés

- [ ] Tester `e()`, `author_url_id()`, `project_storage_path()` et la normalisation bibliographique.
- [ ] Tester `api_get_json()` avec cache valide, réponse invalide, timeout et cache périmé.
- [ ] Ajouter des fixtures JSON sans dépendre du réseau pendant les tests.
- [ ] Créer des smoke tests HTTP pour les pages principales.
- [ ] Ajouter un parcours navigateur : recherche → détail → auteur → bibliothèque.

**Critère de validation :** les scénarios critiques sont exécutables localement par une seule commande.

#### 6. Mettre en place une intégration continue

- [ ] Exécuter `php -l` sur les fichiers applicatifs à chaque push.
- [ ] Contrôler les secrets et les fichiers interdits.
- [ ] Vérifier les liens internes et les ressources locales.
- [ ] Exécuter les tests lorsqu’ils seront disponibles.
- [ ] Bloquer le merge si une étape obligatoire échoue.

### P2 — Exploitation et performance

#### 7. Maîtriser la croissance du stockage

- [ ] Supprimer les caches API non consultés depuis une durée définie.
- [ ] Mettre en place une rotation des CSV.
- [ ] Surveiller l’espace disque de `.booktopia_storage/` et `include/cache_api/`.
- [ ] Empêcher un fichier de cache corrompu d’être réutilisé indéfiniment.

#### 8. Ajouter une observabilité légère

- [ ] Journaliser uniquement les erreurs utiles, sans secret ni donnée personnelle.
- [ ] Distinguer échecs Google Books, OpenLibrary, Wikipédia, Unsplash et NASA.
- [ ] Suivre le taux de cache hit et les temps de réponse côté serveur.
- [ ] Ajouter une vérification périodique de la page d’accueil et du certificat TLS.

#### 9. Optimiser les ressources statiques

- [ ] Activer une durée de cache navigateur pour CSS, JS, polices et images locales.
- [ ] Versionner les URLs des assets lors des changements.
- [ ] Vérifier la compression Brotli/Gzip proposée par l’hébergeur.
- [ ] Réduire ou retirer les exemples inutilisés des bibliothèques embarquées.

### P3 — Évolutions produit

- [ ] Étudier des comptes utilisateurs uniquement si la synchronisation multi-appareils devient prioritaire.
- [ ] Migrer les statistiques vers SQLite ou MySQL si le volume dépasse les capacités des CSV.
- [ ] Ajouter une liste « à lire » distincte des favoris.
- [ ] Ajouter des filtres de langue, année et type de publication.
- [ ] Prévoir une stratégie d’accessibilité WCAG 2.2 AA auditée.

## Matrice de validation avant chaque mise en ligne

| Contrôle | Commande / scénario | Résultat attendu |
|---|---|---|
| Syntaxe PHP | `php -l` sur les fichiers hors `jpgraph` | Aucun échec |
| Secrets | recherche de clés, tokens et mots de passe | Aucune valeur réelle versionnée |
| Accueil | chargement à froid puis à chaud | Aucun warning, cache utilisé au second passage |
| Recherche | requête titre et auteur sur cinq pages | Pagination correcte et paramètres conservés |
| Détail | livre avec et sans couverture | Image ou placeholder, aucun bloc vide |
| Auteur | auteur connu et inconnu | Bio française ou fallback, ouvrages affichés si disponibles |
| Favoris | ajout, rechargement, suppression | État cohérent et compteur exact |
| API indisponible | simulation d’un timeout | Page utilisable et message neutre |
| Fichiers sensibles | requête HTTP vers config/CSV | Réponse 403/404 |
| Mobile | largeur 360 px | Aucun débordement horizontal |
| HTTPS | navigation complète | Aucun contenu mixte |

## Définition de « prêt pour publication »

Une version peut être publiée lorsque :

- la syntaxe PHP est valide ;
- aucun secret n’est inclus dans le commit ou l’archive ;
- les pages critiques fonctionnent avec et sans réponse API ;
- les fichiers sensibles restent inaccessibles ;
- l’interface ne présente ni warning ni chemin serveur ;
- les sauvegardes de production sont disponibles ;
- un retour à la version précédente est possible.
