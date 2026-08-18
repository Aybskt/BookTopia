<?php
$des = 'Découvrez le projet BookTopia, son équipe et ses fonctionnalités.';
$title = 'À propos - BookTopia';
$num = 'L2';
$h1 = 'BookTopia';

$sitePages = [
    ['url' => 'page-de-recherche.php', 'icon' => 'icofont-search-1', 'title' => 'Recherche', 'description' => 'Trouver un livre ou un auteur'],
    ['url' => 'bibliotheque.php', 'icon' => 'icofont-book-alt', 'title' => 'Bibliothèque', 'description' => 'Retrouver vos livres favoris'],
    ['url' => 'statistique.php', 'icon' => 'icofont-chart-histogram', 'title' => 'Statistiques', 'description' => 'Explorer les tendances du site'],
    ['url' => 'a_propos.php', 'icon' => 'icofont-info-circle', 'title' => 'À propos', 'description' => 'Découvrir le projet et l’équipe'],
    ['url' => 'tech.php', 'icon' => 'icofont-tools', 'title' => 'Technologies', 'description' => 'Voir les APIs et services utilisés'],
];

require 'include/header.inc.php';
?>
<main class="about-page">
    <article class="about-hero">
        <div class="about-hero-copy">
            <span class="about-eyebrow">Notre projet</span>
            <h2>La lecture, rendue plus simple et plus inspirante.</h2>
            <p>BookTopia rassemble recherche, découverte et favoris dans une expérience claire, rapide et accessible sur tous les écrans.</p>
            <a href="page-de-recherche.php" class="btn btn-animate">Explorer les livres</a>
        </div>
        <div class="about-hero-mark" aria-hidden="true">
            <span class="about-book-page about-book-left"></span>
            <span class="about-book-page about-book-right"></span>
            <span class="about-book-spine"></span>
        </div>
    </article>

    <section class="about-grid" aria-label="Présentation du projet">
        <article class="about-card">
            <span class="about-card-icon"><i class="icofont-bullseye"></i></span>
            <h3>Notre ambition</h3>
            <p>Proposer un espace littéraire agréable où chacun peut chercher des ouvrages, découvrir leurs auteurs et construire sa propre sélection.</p>
        </article>
        <article class="about-card">
            <span class="about-card-icon"><i class="icofont-users-alt-4"></i></span>
            <h3>Notre équipe</h3>
            <div class="team-members">
                <span><strong>LB</strong>Lounis BOUHADOUN</span>
                <span><strong>AA</strong>Ayoub ABDELLI</span>
            </div>
            <p>Un projet conçu en binôme dans le cadre de la licence informatique à CY Cergy Paris Université.</p>
        </article>
    </section>

    <article class="about-technology">
        <div>
            <span class="about-eyebrow">Sous le capot</span>
            <h3>Une application native, légère et connectée</h3>
            <p>BookTopia utilise PHP, HTML, CSS et JavaScript sans framework, avec un cache local pour limiter les appels réseau.</p>
        </div>
        <ul class="technology-list" aria-label="Technologies utilisées">
            <li>PHP</li><li>HTML5</li><li>CSS3</li><li>JavaScript</li><li>Google Books</li><li>OpenLibrary</li><li>Wikipédia</li>
        </ul>
    </article>

    <article class="site-map-section">
        <div class="site-map-heading">
            <span class="about-eyebrow">Navigation interactive</span>
            <h3>Plan du site</h3>
            <p>Sélectionnez une destination pour accéder directement à la fonctionnalité.</p>
        </div>

        <section class="site-map" aria-label="Plan du site BookTopia">
            <a href="index.php" class="site-map-root">
                <span class="site-map-icon"><i class="icofont-home"></i></span>
                <span><strong>BookTopia</strong><small>Page d’accueil</small></span>
            </a>
            <span class="site-map-trunk" aria-hidden="true"></span>
            <div class="site-map-grid">
                <?php foreach ($sitePages as $page) : ?>
                    <a href="<?php echo e($page['url']); ?>" class="site-map-card">
                        <span class="site-map-icon"><i class="<?php echo e($page['icon']); ?>"></i></span>
                        <span><strong><?php echo e($page['title']); ?></strong><small><?php echo e($page['description']); ?></small></span>
                        <i class="icofont-rounded-right site-map-arrow" aria-hidden="true"></i>
                    </a>
                <?php endforeach; ?>
            </div>
        </section>
    </article>

    <div class="scroll"><i class="icofont-rounded-up"></i></div>
</main>
<?php require 'include/footer.inc.php'; ?>
