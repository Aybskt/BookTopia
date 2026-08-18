<?php

declare(strict_types=1);

require_once("include/functions.inc.php");
include_once("include/util.inc.php");


// Vérifie si l'utilisateur a choisi un mode de couleur
if (isset($_GET['style']) && ($_GET['style'] == 'style' || $_GET['style'] == 'alternatif')) {
    // Met à jour le cookie pour enregistrer la préférence de l'utilisateur
    setcookie('style', $_GET['style'], [
        'expires' => time() + (86400 * 30),
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    // Redirige l'utilisateur vers la même page avec le nouveau paramètre de style
    $redirectParams = $_GET;
    unset($redirectParams['style']);
    $redirectPath = parse_url($_SERVER['REQUEST_URI'] ?? $_SERVER['PHP_SELF'], PHP_URL_PATH);
    $redirectPath = is_string($redirectPath) && $redirectPath !== '' ? $redirectPath : $_SERVER['PHP_SELF'];
    header('Location: ' . $redirectPath . ($redirectParams ? '?' . http_build_query($redirectParams, '', '&', PHP_QUERY_RFC3986) : ''));
    exit;
}

// Vérifie si l'utilisateur a déjà choisi un mode de couleur
if (isset($_COOKIE['style'])) {
    // Si oui, utilise le fichier CSS correspondant
    if ($_COOKIE['style'] === 'style') {
        $stylesheet = 'style.css';
    } else {
        $stylesheet = $_COOKIE['style'] === 'alternatif' ? 'alternatif.css' : 'style.css';
    }
} else {
    // Si non, utilise le mode clair par défaut
    $stylesheet = 'style.css';
}

?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="author" content="Ayoub ABDELLI" />
    <meta name="description" content="<?php echo e($des ?? 'BookTopia'); ?>" />
    <meta name="subject" content="Projet Dev Web <?php echo e($num ?? ''); ?>" />
    <meta name="date" content="2023-02-09T8:36:12+0100" />
    <meta name="lieu" content="CY Cergy Paris Universite" />
    <link rel='stylesheet' href="<?php echo e($stylesheet); ?>" />
    <link rel="stylesheet" href="swiper/swiper-bundle.min.css" />
    <meta name="theme-color" content="#29483d" />
    <link rel="icon" type="image/svg+xml" href="images/favicon.svg" />
    <link rel="stylesheet" href="icofont/icofont.min.css" />

    <title><?php echo e($title ?? 'BookTopia'); ?></title>
</head>

<body>

    <div class="preloader" role="status" aria-live="polite" aria-label="Chargement de BookTopia">
        <div class="preloader-content">
            <div class="preloader-book" aria-hidden="true">
                <span class="preloader-cover"></span>
                <span class="preloader-page preloader-page-one"></span>
                <span class="preloader-page preloader-page-two"></span>
                <span class="preloader-page preloader-page-three"></span>
            </div>
            <p class="preloader-brand">Book<span>Topia</span></p>
            <p class="preloader-label">Ouverture de votre bibliothèque…</p>
            <span class="preloader-progress" aria-hidden="true"><span></span></span>
        </div>
    </div>
    <header>
        <nav>

            <div class="brand">
                <a href="index.php" class="brand-logo" title="Revenir à l'accueil">BookTopia</a>
            </div>

            <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="primary-navigation" aria-label="Ouvrir le menu">
                <span></span>
                <span></span>
                <span></span>
            </button>

            <ul id="primary-navigation">
                <li><a href="page-de-recherche.php">Recherche</a></li>
                <li><a href="bibliotheque.php">Bibliothèque</a></li>
                <li><a href="statistique.php">Statistique</a></li>
                <li><a href="a_propos.php">À propos</a></li>
            </ul>

            <div class="items-mode" aria-label="Choisir le thème">
                <ul>
                    <?php
                    $themeParams = $_GET;
                    unset($themeParams['style']);
                    $themeParams['style'] = 'style';
                    $lightThemeUrl = '?' . http_build_query($themeParams, '', '&', PHP_QUERY_RFC3986);
                    $themeParams['style'] = 'alternatif';
                    $darkThemeUrl = '?' . http_build_query($themeParams, '', '&', PHP_QUERY_RFC3986);
                    ?>
                    <li><a href="<?php echo e($lightThemeUrl); ?>" title="Activer le thème clair" aria-label="Activer le thème clair"><img src="./images/light_mode.png" alt="" /></a></li>
                    <li><a href="<?php echo e($darkThemeUrl); ?>" title="Activer le thème sombre" aria-label="Activer le thème sombre"><img src="./images/dark_mode.png" alt="" /></a></li>
                </ul>
            </div>

        </nav>
    </header>
