<?php
require_once 'include/functions.inc.php';

$query = trim((string) ($_GET['query'] ?? ''));
$searchType = (string) ($_GET['searchType'] ?? 'intitle');
$searchType = in_array($searchType, ['intitle', 'inauthor'], true) ? $searchType : 'intitle';
$startIndex = filter_input(INPUT_GET, 'startIndex', FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
$startIndex = $startIndex === false || $startIndex === null ? 0 : $startIndex;
$maxResults = 10;
$startIndex = min($startIndex, 4 * $maxResults);

if ($query !== '') {
    $isNewSearch = !isset($_COOKIE['recherche']) || (string) $_COOKIE['recherche'] !== $query;
    setcookie('recherche', $query, [
        'expires' => time() + (86400 * 365),
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    if ($isNewSearch) {
        append_csv_row('dataRecherche.csv', [date('Y-m-d H:i:s'), $query, $_SERVER['REMOTE_ADDR'] ?? '']);
    }
}

$des = 'Rechercher un livre ou un auteur sur BookTopia';
$title = 'Recherche - BookTopia';
$num = 'L2';
$h1 = 'BookTopia';
require 'include/header.inc.php';
?>
<main>
    <article>
        <h3>Recherche par titre ou auteur</h3>
        <form method="get" class="form">
            <input type="text" name="query" value="<?php echo e($query); ?>" placeholder="Rechercher des livres" minlength="2" title="Entrez au moins 2 caractères" required />
            <select name="searchType">
                <option value="intitle"<?php echo $searchType === 'intitle' ? ' selected' : ''; ?>>Titre</option>
                <option value="inauthor"<?php echo $searchType === 'inauthor' ? ' selected' : ''; ?>>Auteur</option>
            </select>
            <button type="submit" class="btn btn-animate">Rechercher</button>
        </form>

        <?php
        if ($query !== '') {
            $url = 'https://www.googleapis.com/books/v1/volumes?' . http_build_query([
                'q' => $searchType . ':' . $query,
                'startIndex' => $startIndex,
                'maxResults' => $maxResults,
                'projection' => 'lite',
                'printType' => 'books',
                'fields' => 'totalItems,items(id,volumeInfo(title,authors,imageLinks/thumbnail))',
            ], '', '&', PHP_QUERY_RFC3986);
            $data = api_get_json($url);

            if (is_array($data) && !empty($data['items'])) {
                echo '<div class="results">';
                foreach ($data['items'] as $item) {
                    $volumeInfo = $item['volumeInfo'] ?? [];
                    $bookTitle = $volumeInfo['title'] ?? 'Titre non disponible';
                    $authors = isset($volumeInfo['authors']) && is_array($volumeInfo['authors']) ? implode(', ', $volumeInfo['authors']) : 'Auteur inconnu';
                    $thumbnail = $volumeInfo['imageLinks']['thumbnail'] ?? 'images/book-placeholder.svg';
                    $thumbnail = str_replace('http://', 'https://', $thumbnail);
                    $bookId = (string) ($item['id'] ?? '');
                    $authorId = str_replace(' ', '_', trim($authors));

                    echo '<figure>';
                    echo '<a href="details.php?bookId=' . e(rawurlencode($bookId)) . '"><img src="' . e($thumbnail) . '" alt="' . e($bookTitle) . '" title="' . e($bookTitle) . '" class="cover" loading="lazy" decoding="async" onerror="this.onerror=null;this.src=\'images/book-placeholder.svg\';"/></a>';
                    echo '<figcaption><p>Titre : <a href="details.php?bookId=' . e(rawurlencode($bookId)) . '">' . e($bookTitle) . '</a></p>';
                    echo '<p>Auteur : <a href="data_auteur.php?authorName=' . e(rawurlencode($authorId)) . '">' . e($authors) . '</a></p></figcaption>';
                    echo '</figure>';
                }
                echo '</div>';

                $totalItems = max(0, (int) ($data['totalItems'] ?? 0));
                $totalPages = min(5, max(1, (int) ceil($totalItems / $maxResults)));
                $currentPage = min($totalPages, (int) floor($startIndex / $maxResults) + 1);
                $pageUrl = static function ($page) use ($query, $searchType, $maxResults) {
                    return '?' . http_build_query([
                        'query' => $query,
                        'searchType' => $searchType,
                        'startIndex' => (max(1, (int) $page) - 1) * $maxResults,
                    ], '', '&', PHP_QUERY_RFC3986);
                };

                if ($totalPages > 1) {
                    echo '<nav class="pagination" aria-label="Pagination des résultats">';
                    if ($currentPage > 1) {
                        echo '<a href="' . e($pageUrl($currentPage - 1)) . '" class="page-link" aria-label="Page précédente">&laquo;</a>';
                    }
                    for ($page = 1; $page <= $totalPages; $page++) {
                        if ($page === $currentPage) {
                            echo '<span class="current-page current page-link" aria-current="page">' . e($page) . '</span>';
                        } else {
                            echo '<a href="' . e($pageUrl($page)) . '" class="page-link">' . e($page) . '</a>';
                        }
                    }
                    if ($currentPage < $totalPages) {
                        echo '<a href="' . e($pageUrl($currentPage + 1)) . '" class="page-link" aria-label="Page suivante">&raquo;</a>';
                    }
                    echo '</nav>';
                }
            } elseif ($data === null) {
                echo '<p>La recherche est temporairement indisponible. Veuillez réessayer.</p>';
            } else {
                echo '<p>Aucun résultat trouvé.</p>';
            }
        }
        ?>
    </article>
    <article>
        <h3>Les livres les plus populaires</h3>
        <?php popularBooks(); ?>
    </article>
    <div class="scroll"><i class="icofont-rounded-up"></i></div>
</main>
<?php require 'include/footer.inc.php'; ?>
