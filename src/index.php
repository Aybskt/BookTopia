<?php
$des = "BookTopia";
$title = "BookTopia";
$num = "L2";
$h1 = "BookTopia";
require("include/header.inc.php");
$config = booktopia_config();
$heroImages = get_daily_hero_images();
if (!isset($_COOKIE["Langue"]) || empty($_COOKIE["Langue"])) {
    $_COOKIE["Langue"] = "fr-FR";
}


?>
<div class="home swiper">
    <div class="swiper-wrapper">
        <div class="swiper-slide hero-child" style="background-image:url('images/hero-books.webp');background-size:cover;background-position:center;">
            <img src="<?php echo e($heroImages[0]['src']); ?>" alt="<?php echo e($heroImages[0]['alt']); ?>" width="1600" height="900" fetchpriority="high" decoding="async" onerror="this.onerror=null;this.src='<?php echo e($heroImages[0]['fallback']); ?>';" />
            <a class="hero-credit" href="<?php echo e($heroImages[0]['credit_url']); ?>" target="_blank" rel="noopener noreferrer">Photo : <?php echo e($heroImages[0]['credit_name']); ?> · Unsplash</a>

            <section class="hero-text-section">
                <h1 class="hero-name"><?php echo $h1 ?></h1>
                <span class="story">Plongez dans l'univers envoûtant de la lecture avec Booktopia, votre destination littéraire ultime !</span>
            </section>
        </div>
        <div class="swiper-slide hero-child" style="background-image:url('images/hero-library.webp');background-size:cover;background-position:center;">
            <img src="<?php echo e($heroImages[1]['src']); ?>" alt="<?php echo e($heroImages[1]['alt']); ?>" width="1600" height="900" loading="lazy" decoding="async" onerror="this.onerror=null;this.src='<?php echo e($heroImages[1]['fallback']); ?>';" />
            <a class="hero-credit" href="<?php echo e($heroImages[1]['credit_url']); ?>" target="_blank" rel="noopener noreferrer">Photo : <?php echo e($heroImages[1]['credit_name']); ?> · Unsplash</a>
        </div>
    </div>
    <div class="swiper-pagination"></div>
</div>



<main class="home-main">
    <?php

    if (isset($_COOKIE["LivreConsulté"]) && !empty($_COOKIE["LivreConsulté"]) && ($_COOKIE["LivreConsulté"] != "0")) {
        if (isset($_COOKIE["DateConsultee"]) && !empty($_COOKIE["DateConsultee"])) {  //On récupere le cookie de la date de consultation de la Musique, on s'assure qu'il est bien défini, puis on l'affiche

            // On récupère le cookie de l'id du livre, on s'assure qu'il est bien défini, puis on le retranscrit pour l'afficher
            $url = ($config['link_api'] ?? 'https://www.googleapis.com/books/v1/volumes') . "/" . rawurlencode($_COOKIE["LivreConsulté"]);
            if (LienValide($url)) {
                echo "<article>";
                echo "<h3>Dernier livre consulté</h3>\n";
                $obj = api_get_json($url);
                $title = $obj['volumeInfo']['title'] ?? '';
                $idLivre = $_COOKIE["LivreConsulté"];
                $img = isset($obj['volumeInfo']['imageLinks']['thumbnail']) ? str_replace('http://', 'https://', $obj['volumeInfo']['imageLinks']['thumbnail']) . '&printsec=frontcover&img=1&zoom=0&source=gbs_api' : 'images/book-placeholder.svg';


                echo "<figure class=\"cookie\">";
                echo "<a href=\"details.php?bookId=" . e($idLivre) . "\"><img src=\"" . e($img) . "\" class=\"cover\" alt=\"Couverture de " . e($title) . "\" onerror=\"this.onerror=null;this.src='images/book-placeholder.svg';\"/></a>\n";
                echo "<figcaption class=\"name\"><p>Titre du livre : <a href=\"details.php?bookId=" . e($idLivre) . "\">" . e($title) . "</a>, Consulté le : " . e($_COOKIE["DateConsultee"]) . "</p></figcaption>";
                echo "</figure>";
                echo "</article>";
            }
        }
    }
















    ?>


    <article>

        <h3>Les livres en tendance</h3>
        <?php
        echo trendingBooks();


        ?>

    </article>
    <div class="similar-books">
        <article>
            <h3>Les dernières sorties</h3>
            <?php
            echo getNewBooks();

            ?>
        </article>
    </div>
    <div class="scroll">
        <i class="icofont-rounded-up"></i>
    </div>
</main>
<?php

require("include/footer.inc.php");


?>
