# BookTopia — Améliorations restantes avant publication

Date de l'audit : 16 août 2026  
Statut actuel : **publication déconseillée tant que les tâches P0 ne sont pas terminées**

Ce document sert de feuille de route pour finaliser BookTopia avant sa mise en ligne. Les éléments sont classés par priorité et accompagnés de critères de validation.

## Légende

- **P0 — Bloquant** : indispensable avant toute publication.
- **P1 — Important** : à terminer avant l'ouverture au public.
- **P2 — Qualité** : amélioration professionnelle fortement recommandée.
- **P3 — Évolution** : peut être planifiée après la première version stable.

---

## P0 — Sécurité et déploiement

### 1. Préparer un paquet de déploiement propre

- [ ] Utiliser exclusivement `src/` comme racine publique du serveur web.
- [ ] Ne jamais publier `storage/`, `tmp/`, `doc/`, les rapports PDF/ODT ou `src.zip`.
- [ ] Supprimer `src.zip` du paquet final : cette archive contient d'anciennes copies de fichiers sensibles.
- [ ] Ajouter un `.gitignore` pour exclure les secrets, caches, fichiers temporaires et données statistiques.
- [ ] Créer une liste explicite des fichiers autorisés dans le paquet de production.

**Validation :** aucun fichier de configuration, CSV, cache, rapport ou fichier temporaire ne doit être accessible depuis une URL publique.

### 2. Renouveler et protéger les clés API

- [ ] Révoquer les anciennes clés Google Books, Unsplash, NASA, IPinfo et IP2Location.
- [ ] Générer de nouvelles clés.
- [ ] Stocker les secrets dans des variables d'environnement ou un fichier hors de la racine publique.
- [ ] Restreindre chaque clé par domaine, adresse IP ou API autorisée lorsque le fournisseur le permet.
- [ ] Ne jamais commiter de secrets dans Git.

**Validation :** une recherche globale dans le paquet publié ne doit trouver aucune clé API.

### 3. Réduire JpGraph aux fichiers nécessaires

- [ ] Supprimer `src/jpgraph/docs/` du paquet de production.
- [ ] Supprimer `src/jpgraph/src/Examples/` du paquet de production.
- [ ] Retirer les démonstrations, tests, générateurs, exemples de captcha et outils d'affichage du code source.
- [ ] Conserver uniquement les bibliothèques requises par les trois graphiques.
- [ ] Vérifier que la licence JpGraph correspond à l'usage prévu du site.

**Validation :** les trois graphiques fonctionnent, mais aucune documentation ni page d'exemple JpGraph n'est accessible publiquement.

### 4. Configurer un vrai serveur de production

- [ ] Ne pas utiliser `php -S` pour la publication.
- [ ] Configurer Apache ou Nginx avec `src/` comme DocumentRoot.
- [ ] Autoriser uniquement GET, HEAD et les POST réellement nécessaires.
- [ ] Désactiver TRACE et bloquer les méthodes inutiles.
- [ ] Désactiver l'indexation des dossiers.
- [ ] Reproduire les protections `.htaccess` dans Nginx si Apache n'est pas utilisé.
- [ ] Activer HTTPS et rediriger HTTP vers HTTPS.

**Validation :** TRACE, PUT et DELETE reçoivent un statut 405 ou 403 ; toutes les pages utilisent HTTPS.

### 5. Masquer les erreurs techniques

- [ ] Configurer `display_errors=Off` en production.
- [ ] Configurer `log_errors=On` avec un fichier non public.
- [ ] Masquer la version PHP et l'en-tête `X-Powered-By`.
- [ ] Corriger `$_SERVER['HTTP_USER_AGENT']` avec une valeur de fallback.
- [ ] Vérifier le site avec un User-Agent absent et des paramètres volontairement invalides.

**Validation :** aucune erreur PHP, stack trace ou chemin Windows/Linux n'apparaît dans une réponse HTML.

### 6. Ajouter les en-têtes HTTP de sécurité

- [ ] `Content-Security-Policy`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `Referrer-Policy`
- [ ] `Permissions-Policy`
- [ ] `frame-ancestors` dans la CSP ou une protection équivalente contre l'intégration en iframe.
- [ ] `Strict-Transport-Security` après activation complète de HTTPS.

**Validation :** les en-têtes sont présents sur toutes les pages HTML et les graphiques.

---

## P1 — Protection des actions et des données

### 7. Protéger les formulaires contre le CSRF

- [ ] Démarrer une session de manière sécurisée.
- [ ] Générer un jeton CSRF.
- [ ] Ajouter le jeton aux formulaires d'ajout et de suppression des favoris.
- [ ] Refuser toute action POST sans jeton valide.
- [ ] Utiliser le modèle Post/Redirect/Get après chaque action.

**Validation :** une requête POST forgée sans jeton ne peut ni ajouter ni vider les favoris.

### 8. Uniformiser la sécurité des cookies

- [ ] Appliquer `Secure`, `HttpOnly` et `SameSite=Lax` aux cookies utiles.
- [ ] Réduire leur durée de conservation.
- [ ] Supprimer les cookies `LivreConsulté`, `AuteurConsultée`, `DateConsultee` et `recherche` s'ils ne sont pas réellement utilisés.
- [ ] Supprimer la pseudo-affectation de langue dans `$_COOKIE` si elle ne crée aucun vrai cookie.
- [ ] Vérifier le comportement du thème et des favoris après expiration des cookies.

**Validation :** les outils du navigateur ne montrent aucun cookie inutile ou insuffisamment protégé.

### 9. Sécuriser les recherches et les CSV

- [ ] Limiter la recherche côté serveur, par exemple à 120 caractères.
- [ ] Refuser ou normaliser les caractères de contrôle Unicode.
- [ ] Conserver la validation stricte du type de recherche.
- [ ] Neutraliser les cellules CSV commençant par `=`, `+`, `-` ou `@`.
- [ ] Ne journaliser qu'une seule fois une recherche paginée.
- [ ] Ajouter une limitation simple du débit des recherches.
- [ ] Limiter la taille maximale des fichiers statistiques.

**Validation :** une recherche très longue ou commençant par une formule ne peut pas dégrader le site ni créer une formule active dans un tableur.

### 10. Encadrer les données personnelles

- [ ] Déterminer si l'enregistrement des adresses IP est réellement nécessaire.
- [ ] Anonymiser ou supprimer les adresses IP stockées.
- [ ] Définir une durée de conservation des statistiques.
- [ ] Ajouter une politique de confidentialité accessible depuis le pied de page.
- [ ] Expliquer les appels aux services tiers.
- [ ] Retirer la géolocalisation IP de la page Tech publique ou demander un consentement adapté.
- [ ] Prévoir une procédure de suppression des données.

**Validation :** le site décrit clairement les données collectées, leur finalité et leur durée de conservation.

---

## P1 — Robustesse des pages et des APIs

### 11. Corriger les pages d'erreur et les statuts HTTP

- [ ] Transformer la page d'erreur en page PHP capable d'envoyer `http_response_code(404)`.
- [ ] Retourner 404 pour un livre, un auteur ou une route inexistante.
- [ ] Éviter les redirections 302 vers une page qui répond ensuite 200.
- [ ] Ajouter un message clair et des liens vers l'accueil et la recherche.
- [ ] Configurer la vraie page 404 dans Apache ou Nginx.

**Validation :** une URL inexistante et un identifiant invalide renvoient réellement le statut 404.

### 12. Fiabiliser le cache API

- [ ] Déplacer le cache hors de la racine publique si les contraintes du projet le permettent.
- [ ] Écrire les fichiers via un fichier temporaire puis un renommage atomique.
- [ ] Ajouter un nettoyage périodique des caches anciens.
- [ ] Définir une durée maximale pour l'utilisation d'un cache périmé.
- [ ] Journaliser les erreurs 429, timeouts et réponses JSON invalides sans les afficher aux visiteurs.
- [ ] Vérifier les permissions du dossier de cache.

**Validation :** deux appels identiques utilisent le cache, un fichier partiellement écrit ne casse pas la page et le cache ne grandit pas indéfiniment.

### 13. Uniformiser les couvertures et placeholders

- [ ] Remplacer tous les placeholders `via.placeholder.com` par `images/book-placeholder.svg`.
- [ ] Créer un helper commun de normalisation des URL Google Books.
- [ ] Forcer HTTPS pour les images.
- [ ] Éviter d'ajouter deux fois les paramètres Google Books à une URL.
- [ ] Utiliser OpenLibrary `-L.jpg` lorsque `cover_i` existe.
- [ ] Ajouter le fallback local sur toutes les listes de livres.
- [ ] Ajouter `loading="lazy"`, `width` et `height` aux couvertures hors écran.

**Validation :** couper l'accès aux serveurs d'images externes affiche toujours un placeholder local propre sans déformer la page.

### 14. Améliorer la précision des données

- [ ] Préférer `publishedDate` de Google Books après correspondance précise du livre.
- [ ] Conserver `first_publish_year` uniquement comme fallback.
- [ ] Exclure le livre courant des suggestions similaires.
- [ ] Dédupliquer les suggestions par ID ou titre/auteur normalisé.
- [ ] Vérifier les éditions et auteurs multiples.
- [ ] Ajouter des cas de régression pour Atomic Habits, James Clear et Robert Greene.

**Validation :** les titres, couvertures, auteurs et dates restent cohérents entre la recherche, la bibliothèque et la fiche détaillée.

### 15. Réduire les appels réseau

- [ ] Ne pas appeler Wikipédia uniquement pour fabriquer un identifiant d'auteur dans une carte.
- [ ] Charger la biographie complète uniquement sur la page auteur.
- [ ] Réduire les champs demandés par la fiche Google Books détaillée.
- [ ] Mettre en cache les graphiques générés lorsqu'aucune donnée n'a changé.
- [ ] Étudier le chargement parallèle ou différé des blocs secondaires.
- [ ] Mesurer séparément les performances cache froid et cache chaud.

**Validation :** la page d'accueil et les listes restent utilisables même si une API externe est lente ou indisponible.

---

## P2 — SEO et visibilité

### 16. Structurer correctement les pages

- [ ] Ajouter un seul `<h1>` pertinent à chaque page principale.
- [ ] Respecter l'ordre `h1`, `h2`, `h3`.
- [ ] Générer le `<title>` de la fiche avec le titre du livre.
- [ ] Générer le `<title>` auteur avec le nom de l'auteur.
- [ ] Générer des descriptions spécifiques.
- [ ] Supprimer la métadonnée de date statique de 2023.

### 17. Ajouter les fichiers et métadonnées SEO

- [ ] Créer `robots.txt`.
- [ ] Créer un véritable `sitemap.xml`.
- [ ] Ajouter une URL canonique à chaque page indexable.
- [ ] Ajouter les métadonnées Open Graph.
- [ ] Ajouter les métadonnées de partage social utiles.
- [ ] Décider quelles pages techniques ou statistiques doivent être `noindex`.

**Validation :** aucune page importante n'a un titre générique ou plusieurs H1, et le sitemap est valide.

---

## P2 — Accessibilité et expérience utilisateur

### 18. Corriger les formulaires et contrôles

- [ ] Ajouter des `<label>` visibles ou accessibles au champ et au type de recherche.
- [ ] Remplacer le bouton de retour en haut construit avec un `<div>` par un vrai `<button>`.
- [ ] Ajouter un `aria-label` au lien technique du pied de page.
- [ ] Vérifier les états focus au clavier.
- [ ] Vérifier le menu mobile sans souris.
- [ ] Vérifier les contrastes en thème clair et sombre.

### 19. Rendre le preloader résilient

- [ ] Garantir sa disparition si une erreur JavaScript se produit.
- [ ] Ajouter un comportement adapté lorsque JavaScript est désactivé.
- [ ] Respecter `prefers-reduced-motion`.
- [ ] Éviter que le preloader masque une erreur utile trop longtemps.

### 20. Vérifier le responsive

- [ ] Tester 320 px, 375 px, 768 px, 1024 px, 1440 px et écrans larges.
- [ ] Tester l'orientation paysage sur mobile.
- [ ] Vérifier la bibliothèque avec des titres très longs.
- [ ] Vérifier les biographies longues et les images absentes.
- [ ] Vérifier les graphiques sans débordement horizontal.
- [ ] Tester un zoom navigateur à 200 %.

**Validation :** toutes les fonctions essentielles sont utilisables au clavier, sur mobile et avec un zoom à 200 %.

---

## P2 — Dépendances et ressources statiques

### 21. Stabiliser les dépendances front-end

- [ ] Épingler une version précise de Swiper.
- [ ] Héberger localement le JavaScript Swiper correspondant au CSS.
- [ ] Supprimer la dépendance distante IcoFont et utiliser uniquement les fichiers locaux nécessaires.
- [ ] Étudier l'hébergement local des polices Google.
- [ ] Supprimer `icofont/demo.html` du paquet publié.
- [ ] Supprimer les anciennes images et GIF inutilisés.

### 22. Optimiser les ressources

- [ ] Minifier les CSS et JavaScript pour la production.
- [ ] Activer gzip ou Brotli.
- [ ] Ajouter un cache navigateur long pour les ressources versionnées.
- [ ] Versionner les noms ou URL des fichiers CSS/JS lors des mises à jour.
- [ ] Supprimer le CSS inutilisé.

**Validation :** aucun script critique ne dépend d'une URL `latest` et les assets statiques utilisent un cache navigateur adapté.

---

## P2 — Qualité du code et maintenance

### 23. Nettoyer les incohérences PHP

- [ ] Utiliser `__DIR__` pour les inclusions sensibles.
- [ ] Supprimer les variables et fonctions mortes.
- [ ] Supprimer `echo` devant les fonctions qui retournent `void`.
- [ ] Centraliser les fonctions dupliquées comme `dateDuJour()`.
- [ ] Retirer la balise fermante `?>` des fichiers PHP uniquement.
- [ ] Remplacer la détection fragile du navigateur ou supprimer cette information du pied de page.
- [ ] Uniformiser les textes français et leur encodage UTF-8.

### 24. Ajouter des tests automatiques

- [ ] Test de syntaxe PHP sur tous les fichiers applicatifs.
- [ ] Tests de `api_get_json()` avec succès, timeout, 429 et JSON invalide.
- [ ] Tests de `getGoogleBookId()`.
- [ ] Tests des identifiants invalides.
- [ ] Tests d'échappement HTML et de pagination.
- [ ] Tests des statuts 200, 404, 403 et 405.
- [ ] Test des graphiques PNG.
- [ ] Test des thèmes et favoris.
- [ ] Ajouter un contrôle automatique avant chaque déploiement.

### 25. Prévoir l'exploitation du site

- [ ] Ajouter une procédure de sauvegarde des données utiles.
- [ ] Ajouter une rotation des journaux et statistiques.
- [ ] Surveiller les erreurs PHP et les échecs d'API.
- [ ] Prévoir une page de maintenance.
- [ ] Documenter les variables d'environnement nécessaires.
- [ ] Documenter la procédure de déploiement et de retour arrière.

---

## P3 — Évolutions après lancement

- [ ] Ajouter la suppression individuelle d'un favori.
- [ ] Ajouter un état vide plus informatif pour les recherches sans résultat.
- [ ] Ajouter un indicateur discret lorsqu'une donnée provient du cache ou d'un fallback.
- [ ] Ajouter des données structurées Schema.org pour les livres et auteurs.
- [ ] Remplacer progressivement les statistiques CSV par un stockage plus adapté si le trafic augmente.
- [ ] Ajouter une page de statut ou une supervision externe.
- [ ] Envisager une Progressive Web App uniquement après stabilisation de la version web.

---

## Contrôle final avant mise en ligne

- [ ] Toutes les tâches P0 sont terminées.
- [ ] Toutes les tâches P1 sont terminées.
- [ ] Les clés API ont été renouvelées et restreintes.
- [ ] Le paquet de production ne contient aucun secret ni fichier temporaire.
- [ ] Le site fonctionne avec un cache API vide.
- [ ] Le site fonctionne lorsqu'une API est indisponible.
- [ ] Aucun warning PHP n'est visible.
- [ ] Les statuts HTTP sont corrects.
- [ ] HTTPS et les en-têtes de sécurité sont actifs.
- [ ] Les parcours accueil, recherche, pagination, détail, auteur, favoris, statistiques, thèmes, À propos et Tech ont été testés.
- [ ] Les versions mobile, tablette et bureau ont été validées.
- [ ] La politique de confidentialité est publiée.
- [ ] Une sauvegarde et une procédure de retour arrière existent.

## Critère de décision

BookTopia peut être publié lorsque toutes les tâches **P0** et **P1** sont validées, qu'aucun secret n'est présent dans le paquet de production et qu'un test complet a été effectué sur le véritable hébergement HTTPS.
