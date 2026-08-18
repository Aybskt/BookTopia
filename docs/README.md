# Documentation BookTopia

Documentation officielle de la version 2.0, mise à jour le 18 août 2026.

## Documents principaux

| Document | Usage |
|---|---|
| [Rapport PDF](Rapport-de-projet-dev-web.pdf) | Version finale, mise en page pour lecture et impression |
| [Rapport ODT](Rapport-de-projet-dev-web.odt) | Version éditable avec images intégrées |
| [Rapport HTML](Rapport-de-projet-dev-web.html) | Version web responsive et source du PDF |
| [Audit et feuille de route](AMELIORATIONS_AVANT_PUBLICATION.md) | État réel, travail accompli et priorités restantes |
| [Guide de collaboration](PARTAGE_BINOME.md) | Installation, Git, tests, handover et déploiement |
| [Référence PHP](api/html/index.html) | Vue d’ensemble des helpers et fonctions métier |

## Régénérer les livrables

Le rapport HTML est la source de référence. Sous Windows, Microsoft Edge permet de produire le PDF ; l’ODT est généré nativement et reste compatible avec Word et LibreOffice.

```powershell
.\docs\build-report.ps1
```

Options disponibles :

```powershell
.\docs\build-report.ps1 -SkipPdf
.\docs\build-report.ps1 -SkipOdt
```

Le script vérifie les fichiers requis, intègre les captures situées dans `assets/` et refuse un livrable anormalement petit.

## Règles de maintenance

- Mettre à jour la date et la version dans les documents lors d’une livraison majeure.
- Décrire uniquement les fonctions réellement présentes dans le dépôt.
- Ne jamais inclure de clé, jeton, mot de passe, CSV réel ou adresse IP.
- Regénérer PDF et ODT après toute modification du rapport HTML.
- Exécuter `git diff --check` avant de committer.
