<?php
require_once 'include/functions.inc.php';

function dateDuJour($lang)
{
    $lang;
    $date1 = date('Y-m-d');
    $months = array(
        'fr' => array(
            'janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'
        ),
        'en' => array(
            'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'
        )
    );

    $days = array(
        'fr' => array(
            'dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'
        ),
        'en' => array(
            'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'
        )
    );

    if ($lang == 'en') {
        return $days['en'][date('w')] . ', ' . $months['en'][(int)date('m') - 1] . ' ' . date('j') . ', ' . date('Y');
    } elseif ($lang == 'fr') {
        return $days['fr'][date('w')] . ' ' . date('d') . ' ' . $months['fr'][(int)date('m') - 1] . ' ' . date('Y');
    } else {
        return "La langue n'a pas été choisie";
    }
}

$author_name = trim((string) ($_GET['authorName'] ?? ''));
if ($author_name === '' || mb_strlen($author_name, 'UTF-8') > 150) {
    header('Location: error.html');
    exit;
}

if ($author_name !== '') {
    setcookie("AuteurConsultée", $author_name, time() + (86400 * 365));

    append_csv_row('dataAuteur.csv', [date('Y-m-d H:i:s'), $author_name, $_SERVER['REMOTE_ADDR'] ?? '']);
}


setcookie("DateConsultee", dateDuJour("fr"), time() + 365 * 24 * 3600, "/");


$des = "BookTopia";
$title = "Biographie - Auteur";
$num = "";
$h1 = "BookTopia";
require("include/header.inc.php");

if (!isset($_COOKIE["Langue"]) || empty($_COOKIE["Langue"])) {
    $_COOKIE["Langue"] = "fr-FR";
}




?>
<main>
    <?php
    $authorName = $author_name;

    // Get details for the author
    $authorDetails = get_author_details($authorName);
    ?>
    <article class="author-biography">
        <h3>Biographie de <?php echo e($authorDetails['name']); ?></h3>
        <?php if ($authorDetails['image'] !== '') : ?>
            <figure class="author-profile">
                <img src="<?php echo e($authorDetails['image']) ?>" alt="Photo de l'auteur <?php echo e($authorName) ?>" class="auteur" onerror="this.onerror=null;this.src='images/author-placeholder.svg';" />
                <figcaption>
                    <span class="author-source">Biographie en français</span>
                    <?php if ($authorDetails['bio'] !== '') : ?>
                        <p><?php echo e($authorDetails['bio']) ?></p>
                    <?php else : ?>
                        <p>Aucune biographie trouvée pour cet auteur.</p>
                    <?php endif; ?>
                </figcaption>
            </figure>
        <?php endif; ?>
    </article>

    <article>
        <?php
        $authorName = $author_name;
        $topBooks = get_top_books_by_author($authorName);
        if ($authorName !== null && strpos($authorName, "_") !== false) {
            $authorName = str_replace("_", " ", $authorName);
        }

        // Display the top 4 books by the author
        echo "<h3>Top 3 livres de " . e($authorName) . "</h3>";
        echo "<div class='book-grid'>";
        if (!empty($topBooks)) {
            foreach ($topBooks as $book) {
                $googleBookId = !empty($book['google_id']) ? (string) $book['google_id'] : null;
                $bookImage = $book['image_url'];
                if ($bookImage === 'images/book-placeholder.svg' && $googleBookId !== null) {
                    $googleVolume = api_get_json('https://www.googleapis.com/books/v1/volumes/' . rawurlencode($googleBookId) . '?fields=volumeInfo/imageLinks/thumbnail');
                    if (!empty($googleVolume['volumeInfo']['imageLinks']['thumbnail'])) {
                        $bookImage = str_replace('http://', 'https://', $googleVolume['volumeInfo']['imageLinks']['thumbnail']);
                    }
                }
                $googleCoverFallback = $googleBookId !== null
                    ? 'https://books.google.com/books/content?' . http_build_query([
                        'id' => $googleBookId,
                        'printsec' => 'frontcover',
                        'img' => 1,
                        'zoom' => 2,
                        'source' => 'gbs_api',
                    ], '', '&', PHP_QUERY_RFC3986)
                    : '';
                echo "<figure>";
                if ($googleBookId !== null) {
                    echo "<a href=\"details.php?bookId=" . e($googleBookId) . "\"><img alt=\"Couverture de " . e($book['title']) . "\" class=\"cover\" src=\"" . e($bookImage) . "\" data-fallback-src=\"" . e($googleCoverFallback) . "\" title=\"" . e($book['title']) . " par " . e($authorName) . "\" onerror=\"this.onerror=function(){this.onerror=null;this.src='images/book-placeholder.svg';};this.src=this.dataset.fallbackSrc;\"/></a>";
                } else {
                    echo "<img alt=\"Couverture de " . e($book['title']) . "\" class=\"cover\" src=\"" . e($bookImage) . "\" title=\"" . e($book['title']) . " par " . e($authorName) . "\" onerror=\"this.onerror=null;this.src='images/book-placeholder.svg';\"/>";
                }
                echo "<figcaption>";
                echo "<p>Titre : ";
                if ($googleBookId !== null) {
                    echo "<a href=\"details.php?bookId=" . e($googleBookId) . "\">" . e($book['title']) . "</a>";
                } else {
                    echo e($book['title']);
                }
                echo "</p>";
                echo "<p>Publié en : " . e($book['published_date']) . "</p>";
                echo "<p>ISBN : " . e($book['isbn']) . "</p>";
                echo "</figcaption>";
                echo "</figure>";
            }
        } else {
            echo "<p>Aucun livre trouvé pour cet auteur.</p>";
        }
        echo "</div>";
        ?>

    </article>
    <div class="scroll">
        <i class="icofont-rounded-up"></i>
    </div>
</main>

<?php

require("include/footer.inc.php");


?>
