<?php


/**
 * Compte le nombre de visiteur du site web 
 * @return Int: le nombre de visite
 */

function compteur()
{
    static $visits_count = null;

    if ($visits_count !== null) {
        echo "Nombre de visites : " . $visits_count;
        return;
    }

    $file_path = project_storage_path('visits.txt');

    $file_handle = @fopen($file_path, "c+");
    if (!$file_handle) {
        echo "Nombre de visites indisponible";
        return;
    }

    flock($file_handle, LOCK_EX);

    $visits_count = 0;
    clearstatcache(true, $file_path);
    $file_size = filesize($file_path);
    if ($file_size > 0) {
        $contents = fread($file_handle, $file_size);
        $visits_count = intval($contents);
    }

    $visits_count++;

    fseek($file_handle, 0);
    fwrite($file_handle, "$visits_count");
    fflush($file_handle);

    flock($file_handle, LOCK_UN);
    fclose($file_handle);

    echo "Nombre de visites : " . $visits_count;
}

function project_storage_path($filename = '')
{
    $webRoot = dirname(__DIR__);
    $projectStorageDir = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'storage';
    $hostingRoot = dirname(__DIR__, 3);
    $privateRoot = $hostingRoot . DIRECTORY_SEPARATOR . 'private';
    $privateStorageDir = $privateRoot . DIRECTORY_SEPARATOR . 'storage';
    $infinityFreeStorageDir = $webRoot . DIRECTORY_SEPARATOR . '.booktopia_storage';

    // En production, les données sensibles sont placées dans /private/storage,
    // hors de la racine publique /public/www. Le chemin historique reste utilisé
    // en local. InfinityFree impose de rester dans htdocs : un dossier protégé
    // par .htaccess y est alors utilisé.
    if (basename($webRoot) === 'htdocs') {
        $storageDir = $infinityFreeStorageDir;
    } else {
        $storageDir = is_dir($privateRoot) ? $privateStorageDir : $projectStorageDir;
    }

    if (!is_dir($storageDir)) {
        @mkdir($storageDir, 0775, true);
    }

    return $storageDir . ($filename !== '' ? DIRECTORY_SEPARATOR . basename((string) $filename) : '');
}

function booktopia_config()
{
    static $config = null;
    if ($config === null) {
        $decoded = json_decode((string) @file_get_contents(project_storage_path('config.json')), true);
        $config = is_array($decoded) ? $decoded : [];
    }

    return $config;
}

function append_csv_row($filename, $row)
{
    $handle = @fopen(project_storage_path($filename), 'ab');
    if ($handle === false) {
        return false;
    }

    $written = false;
    if (flock($handle, LOCK_EX)) {
        $written = fputcsv($handle, $row) !== false;
        fflush($handle);
        flock($handle, LOCK_UN);
    }
    fclose($handle);

    return $written;
}








/**
 * Fonction qui permets d'avoir le style utilisé de la page web
 * @return String : la valeur de $style
 */

function get_style(): string
{
    $style = "style"; // valeur par défaut si $_GET['style'] n'est pas défini

    if (isset($_GET['style'])) { // vérifie si $_GET['style'] est défini
        $style = $_GET['style']; // s'il est défini, assigner sa valeur à $style
    }

    return $style; //renvoie la valeur de $style
}

/**
 * Fonction qui permets d'avoir le langue utilisé de la page web
 * @return String : la valeur de $lang 
 */

function get_lang(): string
{
    global $lang; //accéder à une variable déclarée à l'extérieur de la fonction, ici la variable $lang. Cela permet à la fonction d'accéder et de modifier cette variable.
    if (isset($_GET['lang'])) { //vérifier si la variable $_GET['lang'] est définie. Cette variable représente les données passées dans l'URL après le point d'interrogation (?).
        $lang = $_GET['lang']; //affecter la valeur de $_GET['lang'] à la variable $lang si elle est définie.
    } else {
        $lang = "fr"; //affecter alors la valeur "fr" (français) à la variable $lang.
    }
    return $lang; //
}

function api_get_json($url)
{
    static $memoryCache = [];
    static $googleApiKey = null;
    static $unsplashApiKey = null;

    $url = (string) $url;
    if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
        return null;
    }

    $host = parse_url($url, PHP_URL_HOST);
    if (in_array($host, ['www.googleapis.com', 'books.googleapis.com'], true)) {
        if ($googleApiKey === null) {
            $config = booktopia_config();
            $googleApiKey = is_array($config) ? (string) ($config['key_api'] ?? '') : '';
        }

        if ($googleApiKey !== '' && !preg_match('/(?:^|[?&])key=/', $url)) {
            $url .= (str_contains($url, '?') ? '&' : '?') . 'key=' . rawurlencode($googleApiKey);
        }
    }

    $requestHeaders = ['Accept: application/json'];
    if ($host === 'api.unsplash.com') {
        if ($unsplashApiKey === null) {
            $config = booktopia_config();
            $unsplashApiKey = is_array($config) ? (string) ($config['unsplash_key'] ?? '') : '';
        }
        if ($unsplashApiKey === '') {
            return null;
        }
        $requestHeaders[] = 'Authorization: Client-ID ' . $unsplashApiKey;
        $requestHeaders[] = 'Accept-Version: v1';
    }

    if (array_key_exists($url, $memoryCache)) {
        return $memoryCache[$url];
    }

    $cacheDir = __DIR__ . '/cache_api/';
    if (!is_dir($cacheDir)) {
        @mkdir($cacheDir, 0775, true);
    }

    $cacheFile = __DIR__ . '/cache_api/' . sha1($url) . '.json';
    $cachedJson = is_file($cacheFile) ? @file_get_contents($cacheFile) : false;

    if (
        is_string($cachedJson)
        && filemtime($cacheFile) >= time() - 900
    ) {
        $cachedData = json_decode($cachedJson, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            $memoryCache[$url] = $cachedData;
            return $cachedData;
        }
    }

    $ch = curl_init($url);
    if ($ch === false) {
        return null;
    }

    $urlPath = (string) parse_url($url, PHP_URL_PATH);
    $isOpenLibraryFastList = $host === 'openlibrary.org'
        && (str_starts_with($urlPath, '/trending/') || ($urlPath === '/search.json' && str_contains($url, 'sort=readinglog')));
    $isGoogleBooksSearch = in_array($host, ['www.googleapis.com', 'books.googleapis.com'], true)
        && $urlPath === '/books/v1/volumes';
    $isUnsplashRequest = $host === 'api.unsplash.com';

    $connectTimeoutMs = $isUnsplashRequest ? 1000 : ($isOpenLibraryFastList ? 700 : ($isGoogleBooksSearch ? 1000 : 2000));
    $timeoutMs = $isUnsplashRequest ? 2800 : ($isOpenLibraryFastList ? 1200 : ($isGoogleBooksSearch ? 2200 : 3000));

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT_MS => $connectTimeoutMs,
        CURLOPT_TIMEOUT_MS => $timeoutMs,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_ENCODING => '',
        CURLOPT_USERAGENT => 'BookTopia/1.0',
        CURLOPT_HTTPHEADER => $requestHeaders,
    ]);

    $json = curl_exec($ch);
    $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (!is_string($json) || $statusCode < 200 || $statusCode >= 300) {
        if (is_string($cachedJson)) {
            $staleData = json_decode($cachedJson, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $memoryCache[$url] = $staleData;
                return $staleData;
            }
        }
        if (is_dir($cacheDir) && is_writable($cacheDir)) {
            @file_put_contents($cacheFile, 'null', LOCK_EX);
        }
        $memoryCache[$url] = null;
        return null;
    }

    $data = json_decode($json, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        $memoryCache[$url] = null;
        return null;
    }

    if (is_dir($cacheDir) && is_writable($cacheDir)) {
        @file_put_contents($cacheFile, $json, LOCK_EX);
    }

    $memoryCache[$url] = $data;
    return $data;
}

function e($value)
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function get_daily_hero_images()
{
    $fallbackImages = [
        [
            'src' => 'images/hero-books.webp',
            'fallback' => 'images/hero-books.svg',
            'alt' => 'Grande salle de lecture entourée de bibliothèques',
            'credit_url' => 'https://unsplash.com/photos/people-sitting-inside-building-nYToduYJH-c?utm_source=booktopia&utm_medium=referral',
            'credit_name' => 'Clay Banks',
        ],
        [
            'src' => 'images/hero-library.webp',
            'fallback' => 'images/hero-library.svg',
            'alt' => 'Bibliothèque historique et espace de lecture élégant',
            'credit_url' => 'https://unsplash.com/photos/person-sitting-inside-library-wX_zbzIxclA?utm_source=booktopia&utm_medium=referral',
            'credit_name' => 'Sebastien LE DEROUT',
        ],
    ];
    $cacheFile = project_storage_path('daily_hero_images.json');
    $parisNow = new DateTimeImmutable('now', new DateTimeZone('Europe/Paris'));
    $today = $parisNow->format('Y-m-d');
    $cached = json_decode((string) @file_get_contents($cacheFile), true);

    if (is_array($cached) && ($cached['date'] ?? '') === $today && isset($cached['images']) && count($cached['images']) === 2) {
        return $cached['images'];
    }

    $response = api_get_json('https://api.unsplash.com/photos/random?' . http_build_query([
        'query' => 'library books reading',
        'orientation' => 'landscape',
        'count' => 2,
        'content_filter' => 'high',
    ], '', '&', PHP_QUERY_RFC3986));
    $dailyImages = [];

    if (is_array($response)) {
        foreach ($response as $index => $photo) {
            $rawUrl = (string) ($photo['urls']['raw'] ?? '');
            $photoUrl = (string) ($photo['links']['html'] ?? '');
            $photographer = trim((string) ($photo['user']['name'] ?? ''));
            if (
                filter_var($rawUrl, FILTER_VALIDATE_URL) === false
                || parse_url($rawUrl, PHP_URL_HOST) !== 'images.unsplash.com'
                || filter_var($photoUrl, FILTER_VALIDATE_URL) === false
                || !str_ends_with((string) parse_url($photoUrl, PHP_URL_HOST), 'unsplash.com')
                || $photographer === ''
            ) {
                continue;
            }

            $separator = str_contains($rawUrl, '?') ? '&' : '?';
            $dailyImages[] = [
                'src' => $rawUrl . $separator . 'auto=format&fit=crop&w=1600&h=900&q=80',
                'fallback' => $fallbackImages[$index]['src'] ?? 'images/hero-books.webp',
                'alt' => trim((string) ($photo['alt_description'] ?? '')) ?: 'Univers de la lecture et des bibliothèques',
                'credit_url' => $photoUrl . (str_contains($photoUrl, '?') ? '&' : '?') . 'utm_source=booktopia&utm_medium=referral',
                'credit_name' => $photographer,
            ];
        }
    }

    if (count($dailyImages) !== 2) {
        return is_array($cached) && isset($cached['images']) && count($cached['images']) === 2
            ? $cached['images']
            : $fallbackImages;
    }

    @file_put_contents($cacheFile, json_encode([
        'date' => $today,
        'images' => $dailyImages,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);

    return $dailyImages;
}

function author_url_id($authorName)
{
    return str_replace(' ', '_', trim((string) $authorName));
}

function get_similar_books($currentBookId, $volumeInfo, $limit = 3)
{
    $limit = max(1, min(6, (int) $limit));
    $volumeInfo = is_array($volumeInfo) ? $volumeInfo : [];
    $authors = isset($volumeInfo['authors']) && is_array($volumeInfo['authors']) ? $volumeInfo['authors'] : [];
    $primaryAuthor = trim((string) ($authors[0] ?? ''));
    $categories = isset($volumeInfo['categories']) && is_array($volumeInfo['categories']) ? $volumeInfo['categories'] : [];
    $primaryCategory = trim((string) ($categories[0] ?? ''));
    $currentTitle = trim((string) ($volumeInfo['title'] ?? ''));

    if ($primaryAuthor !== '') {
        $query = 'inauthor:"' . $primaryAuthor . '"';
    } elseif ($primaryCategory !== '') {
        $query = 'subject:"' . $primaryCategory . '"';
    } else {
        $query = 'intitle:"' . $currentTitle . '"';
    }

    $url = 'https://www.googleapis.com/books/v1/volumes?' . http_build_query([
        'q' => $query,
        'orderBy' => 'relevance',
        'maxResults' => 10,
        'projection' => 'lite',
        'printType' => 'books',
        'fields' => 'items(id,volumeInfo(title,authors,imageLinks/thumbnail))',
    ], '', '&', PHP_QUERY_RFC3986);
    $response = api_get_json($url);
    $candidates = is_array($response) && isset($response['items']) && is_array($response['items'])
        ? $response['items']
        : [];

    $fallbackCandidates = [
        ['id' => '-a5puQEACAAJ', 'volumeInfo' => ['title' => 'Atomic Habits', 'authors' => ['James Clear']]],
        ['id' => 'afCxg5sogvAC', 'volumeInfo' => ['title' => 'The 48 Laws of Power', 'authors' => ['Robert Greene']]],
        ['id' => 'ZIGxEAAAQBAJ', 'volumeInfo' => ['title' => 'Persuasion', 'authors' => ['Jane Austen']]],
        ['id' => 'v7VPEQAAQBAJ', 'volumeInfo' => ['title' => 'The Street of Crocodiles', 'authors' => ['Bruno Schulz']]],
    ];
    $candidates = array_merge($candidates, $fallbackCandidates);

    $normalize = static function ($value) {
        $value = mb_strtolower(trim((string) $value), 'UTF-8');
        return trim((string) preg_replace('/[^\p{L}\p{N}]+/u', ' ', $value));
    };
    $currentTitleKey = $normalize($currentTitle);
    $seen = [];
    $books = [];

    foreach ($candidates as $candidate) {
        $id = trim((string) ($candidate['id'] ?? ''));
        $candidateInfo = isset($candidate['volumeInfo']) && is_array($candidate['volumeInfo']) ? $candidate['volumeInfo'] : [];
        $title = trim((string) ($candidateInfo['title'] ?? ''));
        $titleKey = $normalize($title);
        if ($id === '' || $id === (string) $currentBookId || $titleKey === '' || $titleKey === $currentTitleKey || isset($seen[$titleKey])) {
            continue;
        }
        $seen[$titleKey] = true;
        if (empty($candidateInfo['imageLinks']['thumbnail'])) {
            $candidateInfo['imageLinks']['thumbnail'] = 'https://books.google.com/books/content?' . http_build_query([
                'id' => $id,
                'printsec' => 'frontcover',
                'img' => 1,
                'zoom' => 2,
                'source' => 'gbs_api',
            ], '', '&', PHP_QUERY_RFC3986);
        }
        $books[] = ['id' => $id, 'volumeInfo' => $candidateInfo];
        if (count($books) >= $limit) {
            break;
        }
    }

    return $books;
}


/**

*Récupère les livres les plus populaires de la semaine depuis l'API Open Library et affiche une grille de couvertures de livres avec leur titre et leur auteur.
*@param int $num_books Le nombre de livres à afficher (3 par défaut)
*@return void
*/


/**
 * The code contains PHP functions for retrieving and displaying information about popular and new
 * books from various APIs, including OpenLibrary and Google Books, as well as author details from
 * Wikipedia.
 * 
 * @param num_books The `num_books` parameter is used in several functions to specify the number of
 * books to retrieve or display. It allows the functions to be flexible and retrieve a variable number
 * of books based on the provided value. If the `num_books` parameter is not provided when calling
 * these functions, it defaults to
 * 
 * @return void The code provided contains several functions related to retrieving and displaying book
 * information from various APIs. Here is a summary of the functions and what they do:
 */
function trendingBooks($num_books = 3): void
{
    $link_api = 'https://openlibrary.org/trending/weekly.json?' . http_build_query([
        'limit' => $num_books,
    ], '', '&', PHP_QUERY_RFC3986);
    $obj = api_get_json($link_api);
    if ($obj === null || !isset($obj['works']) || !is_array($obj['works'])) {
        // OpenLibrary peut être momentanément inaccessible depuis certains
        // hébergeurs gratuits. Ces données de secours conservent la section
        // fonctionnelle jusqu'au prochain appel réussi (mis en cache 15 min).
        $obj = [
            'works' => [
                ['title' => 'Atomic Habits', 'author_name' => ['James Clear'], 'cover_i' => 12539702, 'first_publish_year' => 2016, 'google_book_id' => '-a5puQEACAAJ'],
                ['title' => "Esquire's The New Rules for Men", 'author_name' => ['Esquire'], 'cover_i' => 15123375, 'first_publish_year' => 2016, 'google_book_id' => 'eY8BswEACAAJ'],
                ['title' => 'The 48 Laws of Power', 'author_name' => ['Robert Greene'], 'cover_i' => 6424160, 'first_publish_year' => 1998, 'google_book_id' => 'afCxg5sogvAC'],
            ],
        ];
    }

    $obj = $obj['works'];

    echo "<div class='book-grid'>";

    foreach ($obj as $book) {
        if ($num_books-- <= 0) break;

        $title = $book['title'] ?? 'Titre non disponible';
        $authorNames = $book['author_name'] ?? [];
        $author = is_array($authorNames) ? implode(", ", $authorNames) : $authorNames;
        if ($author === '') {
            $author = 'Auteur inconnu';
        }

        $knownGoogleIds = [
            'atomic habits|james clear' => '-a5puQEACAAJ',
            "esquire's the new rules for men|esquire" => 'eY8BswEACAAJ',
            'the 48 laws of power|robert greene' => 'afCxg5sogvAC',
        ];
        $knownLocalCovers = [
            'atomic habits|james clear' => 'images/trending-atomic-habits.jpg',
            "esquire's the new rules for men|esquire" => 'images/trending-esquire.jpg',
            'the 48 laws of power|robert greene' => 'images/trending-48-laws.jpg',
        ];
        $knownKey = mb_strtolower(trim((string) $title) . '|' . trim((string) $author), 'UTF-8');
        $bookId = $book['cover_i'] ?? null;
        $coverUrl = $knownLocalCovers[$knownKey]
            ?? (($bookId !== null) ? "https://covers.openlibrary.org/b/id/{$bookId}-L.jpg" : 'images/book-placeholder.svg');
        $googleBookId = isset($book['google_book_id'])
            ? (string) $book['google_book_id']
            : ($knownGoogleIds[$knownKey] ?? getGoogleBookId($title, $author));
        $authorId = author_url_id($author);
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
            echo "<a href=\"details.php?bookId=" . e($googleBookId) . "\"><img alt=\"" . e($title) . " by " . e($author) . "\" class=\"cover\" src=\"" . e($coverUrl) . "\" data-fallback-src=\"" . e($googleCoverFallback) . "\" title=\"" . e($title) . " Par " . e($author) . "\" onerror=\"this.onerror=function(){this.onerror=null;this.src='images/book-placeholder.svg';};this.src=this.dataset.fallbackSrc;\"/></a>";
            echo "<figcaption><p>Titre : <a href=\"details.php?bookId=" . e($googleBookId) . "\">" . e($title) . "</a></p>";
        } else {
            echo "<img alt=\"" . e($title) . " by " . e($author) . "\" class=\"cover\" src=\"" . e($coverUrl) . "\" title=\"" . e($title) . " Par " . e($author) . "\" onerror=\"this.onerror=null;this.src='images/book-placeholder.svg';\"/>";
            echo "<figcaption><p>Titre : " . e($title) . "</p>";
        }
        echo "<p>Auteur:<a href=\"data_auteur.php?authorName=" . e($authorId) . "\">" . e($author) . "</a></p></figcaption>";
        echo "</figure>";
    }

    echo "</div>";
}




/**

 *Cette fonction récupère les informations des livres les plus récents depuis l'API Google Books
 *@param int $num_books Le nombre de livres à récupérer
 *@return void
 */

function getNewBooks($num_books = 3): void
{
    $num_books = max(1, (int) $num_books);
    $apiMaxResults = min(40, max(12, $num_books * 6));
    $link_api = 'https://www.googleapis.com/books/v1/volumes?' . http_build_query([
        'q' => 'subject:fiction',
        'orderBy' => 'newest',
        'maxResults' => $apiMaxResults,
        'projection' => 'lite',
        'printType' => 'books',
        'fields' => 'items(id,volumeInfo(title,authors,publishedDate,imageLinks/thumbnail))',
    ], '', '&', PHP_QUERY_RFC3986);
    $obj = api_get_json($link_api);

    $items = is_array($obj) && isset($obj['items']) && is_array($obj['items'])
        ? $obj['items']
        : [];
    $fallbackItems = [
        ['id' => 'pZqQEQAAQBAJ', 'volumeInfo' => ['title' => 'Etna', 'authors' => ['Paul Yoon'], 'publishedDate' => '2026-08-04', 'imageLinks' => ['thumbnail' => 'https://books.google.com/books/content?id=pZqQEQAAQBAJ&printsec=frontcover&img=1&zoom=2&source=gbs_api']]],
        ['id' => '1kWbEQAAQBAJ', 'volumeInfo' => ['title' => 'This Changes Everything', 'authors' => ['Lisa Scottoline'], 'publishedDate' => '2026-07-14', 'imageLinks' => ['thumbnail' => 'https://books.google.com/books/content?id=1kWbEQAAQBAJ&printsec=frontcover&img=1&zoom=2&source=gbs_api']]],
        ['id' => 'zRfGEQAAQBAJ', 'volumeInfo' => ['title' => 'What We Can Know', 'authors' => ['Ian McEwan'], 'publishedDate' => '2026-06-16', 'imageLinks' => ['thumbnail' => 'https://books.google.com/books/content?id=zRfGEQAAQBAJ&printsec=frontcover&img=1&zoom=2&source=gbs_api']]],
    ];

    $minimumYear = (int) date('Y') - 1;
    $today = date('Y-m-d');
    $recentItems = [];
    $seenIds = [];
    foreach (array_merge($items, $fallbackItems) as $item) {
        $googleBookId = trim((string) ($item['id'] ?? ''));
        $publishedDate = trim((string) ($item['volumeInfo']['publishedDate'] ?? ''));
        if ($googleBookId === '' || isset($seenIds[$googleBookId]) || !preg_match('/^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?/', $publishedDate, $dateParts)) {
            continue;
        }

        $publishedYear = (int) $dateParts[1];
        if ($publishedYear < $minimumYear || (strlen($publishedDate) >= 10 && substr($publishedDate, 0, 10) > $today)) {
            continue;
        }

        $seenIds[$googleBookId] = true;
        $item['_sort_date'] = sprintf(
            '%04d-%02d-%02d',
            $publishedYear,
            isset($dateParts[2]) ? (int) $dateParts[2] : 1,
            isset($dateParts[3]) ? (int) $dateParts[3] : 1
        );
        $recentItems[] = $item;
    }

    usort($recentItems, static function ($left, $right) {
        return strcmp($right['_sort_date'], $left['_sort_date']);
    });
    $obj = ['items' => array_slice($recentItems, 0, $num_books)];

    echo "<div class='book-grid'>";
    foreach ($obj['items'] as $item) {
            $volumeInfo = $item['volumeInfo'] ?? [];

            $title = $volumeInfo['title'] ?? 'Titre non disponible';
            $authors = isset($volumeInfo['authors']) ? implode(", ", $volumeInfo['authors']) : "Auteur inconnu";
            $publishedDate = $volumeInfo['publishedDate'] ?? "Date inconnue";
            $thumbnail = $volumeInfo['imageLinks']['thumbnail'] ?? "images/book-placeholder.svg";
            $thumbnail = str_replace('http://', 'https://', $thumbnail);
            $thumbnail = preg_replace('/([?&])zoom=1(?:&|$)/', '$1zoom=2&', $thumbnail);
            $googleBookId = $item['id'] ?? '';
            $authorId = author_url_id($authors);

            echo "<figure>";
            echo "<a href=\"details.php?bookId=" . e($googleBookId) . "\"><img alt=\"" . e($title) . " by " . e($authors) . "\" class=\"cover\" src=\"" . e($thumbnail) . "\" title=\"" . e($title) . " by " . e($authors) . "\" onerror=\"this.onerror=null;this.src='images/book-placeholder.svg';\"/></a>";
            echo "<figcaption><p>Titre : <a href=\"details.php?bookId=" . e($googleBookId) . "\">" . e($title) . "</a></p> <p>Auteur : <a href=\"data_auteur.php?authorName=" . e($authorId) . "\">" . e($authors) . "</a></p> <p>Publié le : " . e($publishedDate) . "</p></figcaption>";
            echo "</figure>";
    }
    echo "</div>";
}



/**

 *Cette fonction récupère les détails d'un auteur depuis l'API Wikipedia
 *@param string $authorName Le nom de l'auteur
 *@return array Les détails de l'auteur
 */
function get_author_details($authorName)
{
    if (empty($authorName)) {
        return [
            'name' => 'Auteur inconnu',
            'id' => '',
            'bio' => 'Aucun nom d’auteur fourni.',
            'image' => 'images/author-placeholder.svg',
            'books' => [],
        ];
    }

    $authorName = trim($authorName);
    $authorUrlName = author_url_id($authorName);
    $authorDisplayName = str_replace('_', ' ', $authorUrlName);
    $summaryPath = rawurlencode(str_replace(' ', '_', $authorDisplayName));
    $frenchPage = api_get_json('https://fr.wikipedia.org/api/rest_v1/page/summary/' . $summaryPath);
    $isFrenchArticle = is_array($frenchPage)
        && ($frenchPage['type'] ?? '') !== 'disambiguation'
        && !empty($frenchPage['extract']);
    $bio = $isFrenchArticle
        ? (string) $frenchPage['extract']
        : 'La biographie en français de ' . $authorDisplayName . ' n’est pas encore disponible sur Wikipédia.';
    $image = $isFrenchArticle ? ($frenchPage['thumbnail']['source'] ?? $frenchPage['originalimage']['source'] ?? '') : '';

    if ($image === '') {
        $internationalPage = api_get_json('https://en.wikipedia.org/api/rest_v1/page/summary/' . $summaryPath);
        if (is_array($internationalPage) && ($internationalPage['type'] ?? '') !== 'disambiguation') {
            $image = $internationalPage['thumbnail']['source'] ?? $internationalPage['originalimage']['source'] ?? '';
        }
    }
    if ($image === '') {
        $image = 'images/author-placeholder.svg';
    }

    return [
        'name' => $authorDisplayName,
        'id' => $authorUrlName,
        'bio' => $bio,
        'image' => $image,
        'books' => [],
    ];
}



/**

 *Cette fonction permet de récupérer les 3 premiers livres d'un auteur à partir de son nom.
 *@param string $authorName Le nom de l'auteur dont on souhaite récupérer les livres.
 *@return array Un tableau associatif contenant les détails des 3 premiers livres de l'auteur (titre, date de publication, ISBN, URL de l'image de couverture). Si la recherche ne renvoie aucun livre ou si une erreur se produit, un tableau vide est renvoyé.
 */
function get_top_books_by_author($authorName)
{
    if ($authorName !== null && strpos($authorName, "_") !== false) {
        $authorName = str_replace("_", " ", $authorName);
    }
    $authorName = trim((string) $authorName);
    if ($authorName === '') {
        return [];
    }

    $ol_url = 'https://openlibrary.org/search.json?' . http_build_query([
        'author' => $authorName,
        'fields' => 'title,author_name,cover_i,first_publish_year,isbn',
        'sort' => 'editions',
        'limit' => 50,
    ], '', '&', PHP_QUERY_RFC3986);
    $ol_json = api_get_json($ol_url);

    $normalize = static function ($value) {
        $value = mb_strtolower(trim((string) $value), 'UTF-8');
        return trim((string) preg_replace('/[^\p{L}\p{N}]+/u', ' ', $value));
    };
    $normalizedAuthor = $normalize($authorName);
    $books = [];
    $seenTitles = [];
    $bookIndexByTitle = [];

    if (is_array($ol_json) && isset($ol_json['docs']) && is_array($ol_json['docs'])) {
        foreach ($ol_json['docs'] as $book) {
            if (count($books) >= 3) {
                break;
            }
            $bookAuthors = isset($book['author_name']) && is_array($book['author_name']) ? $book['author_name'] : [];
            $isExactAuthor = false;
            foreach ($bookAuthors as $bookAuthor) {
                if ($normalize($bookAuthor) === $normalizedAuthor) {
                    $isExactAuthor = true;
                    break;
                }
            }
            if (!$isExactAuthor) {
                continue;
            }

            $bookTitle = trim((string) ($book['title'] ?? ''));
            $titleKey = $normalize($bookTitle);
            if ($bookTitle === '' || isset($seenTitles[$titleKey])) {
                continue;
            }
            $seenTitles[$titleKey] = true;
            $bookIndexByTitle[$titleKey] = count($books);
            $books[] = [
                'title' => $bookTitle,
                'published_date' => $book['first_publish_year'] ?? 'N\'a pas de publication',
                'isbn' => $book['isbn'][0] ?? 'N\'a pas d\'ISBN',
                'image_url' => isset($book['cover_i']) ? 'https://covers.openlibrary.org/b/id/' . $book['cover_i'] . '-L.jpg' : 'images/book-placeholder.svg',
            ];
        }
    }

    $googleUrl = 'https://www.googleapis.com/books/v1/volumes?' . http_build_query([
        'q' => 'inauthor:"' . $authorName . '"',
        'orderBy' => 'relevance',
        'maxResults' => 10,
        'projection' => 'lite',
        'printType' => 'books',
        'fields' => 'items(id,volumeInfo(title,authors,publishedDate,industryIdentifiers,imageLinks/thumbnail))',
    ], '', '&', PHP_QUERY_RFC3986);
    $googleJson = api_get_json($googleUrl);
    $googleItems = is_array($googleJson) && isset($googleJson['items']) && is_array($googleJson['items']) ? $googleJson['items'] : [];

    foreach ($googleItems as $item) {
        $info = isset($item['volumeInfo']) && is_array($item['volumeInfo']) ? $item['volumeInfo'] : [];
        $itemAuthors = isset($info['authors']) && is_array($info['authors']) ? $info['authors'] : [];
        $isAuthorMatch = false;
        foreach ($itemAuthors as $itemAuthor) {
            $normalizedItemAuthor = $normalize($itemAuthor);
            if ($normalizedItemAuthor === $normalizedAuthor || str_contains($normalizedItemAuthor, $normalizedAuthor)) {
                $isAuthorMatch = true;
                break;
            }
        }
        if (!$isAuthorMatch) {
            continue;
        }

        $bookTitle = trim((string) ($info['title'] ?? ''));
        $titleKey = $normalize($bookTitle);
        if ($bookTitle === '' || $titleKey === '') {
            continue;
        }
        $googleId = trim((string) ($item['id'] ?? ''));
        $thumbnail = $info['imageLinks']['thumbnail'] ?? '';
        if ($thumbnail !== '') {
            $thumbnail = str_replace('http://', 'https://', $thumbnail);
        } elseif ($googleId !== '') {
            $thumbnail = 'https://books.google.com/books/content?' . http_build_query([
                'id' => $googleId,
                'printsec' => 'frontcover',
                'img' => 1,
                'zoom' => 2,
                'source' => 'gbs_api',
            ], '', '&', PHP_QUERY_RFC3986);
        } else {
            $thumbnail = 'images/book-placeholder.svg';
        }

        if (isset($bookIndexByTitle[$titleKey])) {
            $index = $bookIndexByTitle[$titleKey];
            $books[$index]['google_id'] = $googleId;
            if (($books[$index]['image_url'] ?? '') === 'images/book-placeholder.svg') {
                $books[$index]['image_url'] = $thumbnail;
            }
            continue;
        }
        if (count($books) >= 3) {
            continue;
        }

        $isbn = 'N\'a pas d\'ISBN';
        $identifiers = isset($info['industryIdentifiers']) && is_array($info['industryIdentifiers']) ? $info['industryIdentifiers'] : [];
        foreach ($identifiers as $identifier) {
            if (in_array($identifier['type'] ?? '', ['ISBN_13', 'ISBN_10'], true) && !empty($identifier['identifier'])) {
                $isbn = (string) $identifier['identifier'];
                break;
            }
        }
        $seenTitles[$titleKey] = true;
        $bookIndexByTitle[$titleKey] = count($books);
        $books[] = [
            'title' => $bookTitle,
            'published_date' => $info['publishedDate'] ?? 'N\'a pas de publication',
            'isbn' => $isbn,
            'image_url' => $thumbnail,
            'google_id' => $googleId,
        ];
    }

    return array_slice($books, 0, 3);
}


/**
 *Cette fonction permet de récupérer l'identifiant Google Books d'un livre à partir de son titre et de l'auteur.
 *@param string $title Le titre du livre.
 *@param string $author Le nom de l'auteur du livre.
 *@return string|null L'identifiant Google Books du premier livre correspondant à la recherche, ou null s'il n'y a pas de résultat ou si une erreur se produit.
 */

function getGoogleBookId($title, $author)
{
    if (trim((string) $title) === '' || trim((string) $author) === '') {
        return null;
    }

    $title = trim((string) $title);
    $author = trim((string) $author);
    $query = 'intitle:"' . $title . '" inauthor:"' . $author . '"';
    $link_api = 'https://www.googleapis.com/books/v1/volumes?' . http_build_query([
        'q' => $query,
        'maxResults' => 10,
        'projection' => 'lite',
        'printType' => 'books',
        'fields' => 'items(id,volumeInfo(title,authors,publishedDate))',
    ], '', '&', PHP_QUERY_RFC3986);
    $obj = api_get_json($link_api);

    if ($obj === null || empty($obj['items']) || !is_array($obj['items'])) {
        return null;
    }

    $normalize = static function ($value) {
        $value = mb_strtolower(trim((string) $value), 'UTF-8');
        $ascii = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $value);
        if ($ascii !== false) {
            $value = $ascii;
        }
        return trim((string) preg_replace('/[^a-z0-9]+/i', ' ', $value));
    };

    $canonicalTitle = static function ($value) use ($normalize) {
        $value = $normalize($value);
        return (string) preg_replace('/^(?:the|a|an|le|la|les|un|une|des)\s+/', '', $value);
    };

    $expectedTitle = $canonicalTitle($title);
    $expectedAuthor = $normalize($author);
    $bestId = null;
    $bestScore = -1;

    foreach ($obj['items'] as $item) {
        $candidateTitle = $canonicalTitle($item['volumeInfo']['title'] ?? '');
        $candidateAuthors = $item['volumeInfo']['authors'] ?? [];
        if (!is_array($candidateAuthors)) {
            $candidateAuthors = [$candidateAuthors];
        }
        $candidateAuthor = $normalize(implode(' ', $candidateAuthors));

        if ($candidateTitle === '' || $candidateAuthor === '' || !isset($item['id'])) {
            continue;
        }

        $titleExact = $candidateTitle === $expectedTitle;
        $titleStartsWith = str_starts_with($candidateTitle, $expectedTitle . ' ');
        $authorExact = $candidateAuthor === $expectedAuthor;
        $authorContains = str_contains($candidateAuthor, $expectedAuthor);
        if ((!$titleExact && !$titleStartsWith) || (!$authorExact && !$authorContains)) {
            continue;
        }

        $score = ($titleExact ? 100 : 60) + ($authorExact ? 40 : 20);
        $score -= max(0, strlen($candidateTitle) - strlen($expectedTitle));
        if ($score > $bestScore) {
            $bestScore = $score;
            $bestId = (string) $item['id'];
        }
    }

    return $bestId;
}


/**
 * Vérifie si un lien URL donné correspond à un livre valide sur Google Books.
 * @param string $url L'URL à vérifier.
 * @return bool Retourne true si l'URL correspond à un livre valide sur Google Books ou pas.
 */

function LienValide($url)
{
    $json = api_get_json($url);

    if ($json === null || !isset($json['kind']) || $json['kind'] !== 'books#volume') {
        return false;
    }

    return true;
}

/**
 * Affiche les livres les plus ajoutés aux journaux de lecture OpenLibrary.
 * @return void
 */
function popularBooks()
{
    $url = 'https://openlibrary.org/search.json?' . http_build_query([
        'q' => 'fiction',
        'fields' => 'key,title,author_name,cover_i,readinglog_count',
        'sort' => 'readinglog',
        'limit' => 6,
    ], '', '&', PHP_QUERY_RFC3986);
    $response = api_get_json($url);
    $books = is_array($response) && isset($response['docs']) && is_array($response['docs'])
        ? $response['docs']
        : [];

    $fallbackBooks = [
        ['title' => 'It Ends With Us', 'author_name' => ['Colleen Hoover'], 'cover_i' => 10473609, 'readinglog_count' => 44270],
        ['title' => "Harry Potter and the Philosopher's Stone", 'author_name' => ['J. K. Rowling'], 'cover_i' => 15155833, 'readinglog_count' => 23587],
        ['title' => 'It Starts with Us', 'author_name' => ['Colleen Hoover'], 'cover_i' => 12749873, 'readinglog_count' => 19506],
    ];
    $knownGoogleIds = [
        'it ends with us|colleen hoover' => 'wmnuDwAAQBAJ',
        "harry potter and the philosopher's stone|j. k. rowling" => 'HFs9AwAAQBAJ',
        'it starts with us|colleen hoover' => 'eIjXzwEACAAJ',
    ];

    $books = array_merge($books, $fallbackBooks);
    $seen = [];
    $displayed = 0;
    echo "<div class='book-grid'>";

    foreach ($books as $book) {
        if ($displayed >= 3) {
            break;
        }

        $title = trim((string) ($book['title'] ?? ''));
        $authorNames = isset($book['author_name']) && is_array($book['author_name']) ? $book['author_name'] : [];
        $author = trim(implode(', ', $authorNames));
        $bookKey = mb_strtolower($title . '|' . $author, 'UTF-8');
        if ($title === '' || $author === '' || isset($seen[$bookKey])) {
            continue;
        }

        $id = $knownGoogleIds[$bookKey] ?? getGoogleBookId($title, $author);
        if ($id === null || $id === '') {
            continue;
        }

        $seen[$bookKey] = true;
        $thumbnail = 'https://books.google.com/books/content?' . http_build_query([
                'id' => $id,
                'printsec' => 'frontcover',
                'img' => 1,
                'zoom' => 2,
                'source' => 'gbs_api',
            ], '', '&', PHP_QUERY_RFC3986);
        $authorId = author_url_id($author);

        echo "<figure>";
        echo "<a href=\"details.php?bookId=" . e($id) . "\"><img alt=\"" . e($title) . " by " . e($author) . "\" class=\"cover\" src=\"" . e($thumbnail) . "\" title=\"" . e($title) . " Par " . e($author) . "\" loading=\"lazy\" decoding=\"async\" fetchpriority=\"low\" onerror=\"this.onerror=null;this.src='images/book-placeholder.svg';\"/></a>";
        echo "<figcaption><p>Titre : <a href=\"details.php?bookId=" . e($id) . "\">" . e($title) . "</a></p> <p>Auteur: <a href=\"data_auteur.php?authorName=" . e($authorId) . "\">" . e($author) . "</a></p></figcaption>";
        echo "</figure>";
        $displayed++;
    }
    echo "</div>";
}

?>
