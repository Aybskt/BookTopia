<?php
require_once 'include/functions.inc.php';

$cookieOptions = [
    'expires' => time() + (86400 * 30),
    'path' => '/',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
];
$decodedFavorites = isset($_COOKIE['favorites']) ? json_decode((string) $_COOKIE['favorites'], true) : [];
$favorites = is_array($decodedFavorites) ? array_values(array_filter($decodedFavorites, static function ($id) {
    return is_string($id) && preg_match('/^[A-Za-z0-9_-]{1,64}$/', $id) === 1;
})) : [];

if (isset($_POST['favorite'])) {
    $bookId = trim((string) ($_POST['bookId'] ?? ''));
    if (preg_match('/^[A-Za-z0-9_-]{1,64}$/', $bookId) === 1 && !in_array($bookId, $favorites, true)) {
        $favorites[] = $bookId;
        $favorites = array_slice($favorites, -5);
        setcookie('favorites', json_encode($favorites), $cookieOptions);
    }
    header('Location: bibliotheque.php');
    exit;
}

if (isset($_POST['clear']) && $_POST['clear'] === 'true') {
    $cookieOptions['expires'] = time() - 3600;
    setcookie('favorites', '', $cookieOptions);
    header('Location: bibliotheque.php');
    exit;
}

$des = 'Votre bibliothèque personnelle BookTopia';
$title = 'Ma bibliothèque';
$num = 'L2';
$h1 = 'BookTopia';
require 'include/header.inc.php';
?>
<main class="library-page">
    <article class="library-panel">
        <h3>Vos livres favoris</h3>
        <div class="results library-shelves">
            <?php if ($favorites) : ?>
                <?php foreach ($favorites as $bookId) : ?>
                    <?php
                    $url = 'https://www.googleapis.com/books/v1/volumes/' . rawurlencode($bookId) . '?langRestrict=fr';
                    $data = api_get_json($url);
                    if (!is_array($data) || isset($data['error'])) {
                        continue;
                    }
                    $title = $data['volumeInfo']['title'] ?? 'Titre non disponible';
                    $author = isset($data['volumeInfo']['authors']) && is_array($data['volumeInfo']['authors']) ? implode(', ', $data['volumeInfo']['authors']) : 'Auteur inconnu';
                    $thumbnail = $data['volumeInfo']['imageLinks']['thumbnail'] ?? 'images/book-placeholder.svg';
                    $thumbnail = str_replace('http://', 'https://', $thumbnail);
                    $authorId = str_replace(' ', '_', trim($author));
                    ?>
                    <figure>
                        <a href="details.php?bookId=<?php echo e(rawurlencode($bookId)); ?>"><img alt="<?php echo e($title . ' par ' . $author); ?>" class="cover" src="<?php echo e($thumbnail); ?>" title="<?php echo e($title . ' par ' . $author); ?>" onerror="this.onerror=null;this.src='images/book-placeholder.svg';" /></a>
                        <figcaption><p class="library-book-title"><a href="details.php?bookId=<?php echo e(rawurlencode($bookId)); ?>" title="<?php echo e($title); ?>"><?php echo e($title); ?></a></p><p>Auteur : <a href="data_auteur.php?authorName=<?php echo e(rawurlencode($authorId)); ?>"><?php echo e($author); ?></a></p></figcaption>
                    </figure>
                <?php endforeach; ?>
            <?php else : ?>
                <figure class="error"><img src="images/error.png" alt="Votre bibliothèque est vide" title="Votre bibliothèque est vide" /><figcaption><p>Votre bibliothèque est vide pour le moment. Ajoutez un livre depuis sa fiche.</p></figcaption></figure>
            <?php endif; ?>
        </div>
        <?php if ($favorites) : ?>
            <form method="post" class="form"><input type="hidden" name="clear" value="true" /><button type="submit" class="btn btn-animate">Vider ma bibliothèque</button></form>
        <?php endif; ?>
    </article>
    <div class="scroll"><i class="icofont-rounded-up"></i></div>
</main>
<?php require 'include/footer.inc.php'; ?>
