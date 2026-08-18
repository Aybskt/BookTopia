# BookTopia

BookTopia est une application web PHP permettant de rechercher des livres, consulter leurs informations, découvrir leurs auteurs et gérer une bibliothèque personnelle.

Site en ligne : [booktopia.fr](https://booktopia.fr)

## Équipe

- Ayoub ABDELLI
- Lounis BOUHADOUN
- Groupe A04

## Fonctionnalités

- recherche de livres et d’auteurs avec pagination ;
- fiches détaillées, couvertures et suggestions similaires ;
- biographies d’auteurs en français ;
- tendances, nouveautés et livres populaires ;
- bibliothèque et favoris ;
- statistiques de consultation ;
- thèmes clair et sombre ;
- interface responsive.

## APIs utilisées

- Google Books API ;
- OpenLibrary API ;
- Wikipedia REST API ;
- Unsplash API ;
- NASA APOD et IPinfo pour la page Tech.

Les réponses externes sont mises en cache côté serveur afin de limiter les appels réseau et les délais d’affichage.

## Installation locale

1. Installer PHP avec l’extension cURL activée.
2. Copier `storage/config.example.json` vers `storage/config.json`.
3. Renseigner les clés API nécessaires dans `storage/config.json`.
4. Démarrer le serveur depuis le dossier `src` :

```bash
php -S localhost:8000
```

5. Ouvrir `http://localhost:8000`.

Les secrets, données de consultation et caches d’exécution sont exclus du dépôt Git.

## Technologies

PHP, HTML5, CSS3, JavaScript, Swiper, JpGraph et APIs REST.

## Licence

Ce projet est distribué sous licence MIT.
