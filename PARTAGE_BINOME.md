# BookTopia — installation locale

## Contenu

- `src/` : site PHP complet, styles, scripts, images et JpGraph.
- `storage/` : configuration locale et fichiers de statistiques vierges.

## Configuration

1. Copier `storage/config.example.json` vers `storage/config.json`.
2. Renseigner les clés API nécessaires dans `storage/config.json`.
3. Ne jamais publier ou versionner le fichier `config.json` rempli.

## Lancement avec XAMPP

Depuis le dossier extrait :

```powershell
cd src
C:\xampp\php\php.exe -S localhost:8000
```

Ouvrir ensuite <http://localhost:8000>.

PHP doit disposer des extensions cURL, JSON, mbstring et GD.
