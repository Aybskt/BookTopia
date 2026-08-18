    <?php
    require_once("include/functions.inc.php");

    function dateDuJour($lang)
    {
        $lang;
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
    $bookId = trim((string) ($_GET['bookId'] ?? ''));
    if ($bookId === '' || preg_match('/^[A-Za-z0-9_-]{1,64}$/', $bookId) !== 1) {
        header('Location: error.html');
        exit;
    }

    if ($bookId !== '') {
        setcookie("LivreConsulté", $bookId, time() + (86400 * 365));

        // Requête à l'API Google Books
        $url = "https://www.googleapis.com/books/v1/volumes/" . rawurlencode($bookId);
        $book = api_get_json($url);
        if ($book === null) {
            header('Location: error.html');
            exit();
        }

        // Récupération du titre du livre
        $title_Book = $book['volumeInfo']['title'] ?? 'Titre non disponible';

        // Enregistrement dans le fichier CSV
        append_csv_row('dataLivre.csv', [date('Y-m-d H:i:s'), $bookId, $title_Book, $_SERVER['REMOTE_ADDR'] ?? '']);
    }


    setcookie("DateConsultee", dateDuJour("fr"), time() + 365 * 24 * 3600, "/");



    $des = "BookTopia";
    $title = "Détail Livre";
    $num = "L2";
    $h1 = "BookTopia";
    require("include/header.inc.php");

    if (!isset($_COOKIE["Langue"]) || empty($_COOKIE["Langue"])) {
        $_COOKIE["Langue"] = "fr-FR";
    }




    ?>

    <main>
        <?php
        $data = $book;
        if ($data === null) {
            echo "Les informations de ce livre sont temporairement indisponibles.";
            exit();
        }

        // Check if the API response contains any book data
        if (empty($data) || isset($data['error'])) {
            echo '<p>Ce livre est introuvable.</p>';
            exit();
        }

        // Extract the book details from the API response
        $title = isset($data['volumeInfo']['title']) ? $data['volumeInfo']['title'] : 'Titre non disponible';
        $authors = isset($data['volumeInfo']['authors']) ? implode(", ", $data['volumeInfo']['authors']) : 'Auteur non disponible';
        $description = isset($data['volumeInfo']['description']) ? strip_tags($data['volumeInfo']['description']) : 'Description non disponible';

        $isbn = isset($data['volumeInfo']['industryIdentifiers']) ? implode(", ", array_column(array_filter($data['volumeInfo']['industryIdentifiers'], function ($item) {
            return in_array($item['type'], ['ISBN_10', 'ISBN_13']);
        }), 'identifier')) : 'ISBN non disponible';
        $isbnValues = isset($data['volumeInfo']['industryIdentifiers']) ? array_values(array_column(array_filter($data['volumeInfo']['industryIdentifiers'], function ($item) {
            return in_array($item['type'] ?? '', ['ISBN_13', 'ISBN_10'], true) && !empty($item['identifier']);
        }), 'identifier')) : [];
        $googleImage = isset($data['volumeInfo']['imageLinks']['thumbnail'])
            ? str_replace('http://', 'https://', $data['volumeInfo']['imageLinks']['thumbnail'])
            : '';
        if (!empty($isbnValues)) {
            $image = 'https://covers.openlibrary.org/b/isbn/' . rawurlencode($isbnValues[0]) . '-L.jpg?default=false';
            $fallbackImage = $googleImage !== '' ? $googleImage : 'images/book-placeholder.svg';
        } elseif ($googleImage !== '') {
            $image = $googleImage;
            $fallbackImage = 'images/book-placeholder.svg';
        } else {
            $image = 'images/book-placeholder.svg';
            $fallbackImage = 'images/book-placeholder.svg';
        }
        $publisher = isset($data['volumeInfo']['publisher']) ? $data['volumeInfo']['publisher'] : 'Editeur non disponible';
        $publishedDate = isset($data['volumeInfo']['publishedDate']) ? $data['volumeInfo']['publishedDate'] : 'Date non disponible';
        $authorId = author_url_id($authors);

        // Output the book details in HTML
        echo "<article>";
        echo "<h3>" . e($title) . "</h3>";
        echo "<figure>";
        echo "<img src='" . e($image) . "' data-fallback-src='" . e($fallbackImage) . "' alt='Couverture de " . e($title) . "' class=\"cover\" title='" . e($title) . "' onerror=\"this.onerror=function(){this.onerror=null;this.src='images/book-placeholder.svg';};this.src=this.dataset.fallbackSrc;\"/>";
        echo "<figcaption>";
        echo "<p><strong>Auteur:</strong> <a href=\"data_auteur.php?authorName=" . e($authorId) . "\">" . e($authors) . "</a></p>";
        echo "<p><strong>ISBN:</strong> " . e($isbn) . "</p>";
        echo "<p><strong>Editeur:</strong> " . e($publisher) . "</p>";
        echo "<p><strong>Date de publication:</strong> " . e($publishedDate) . "</p>";
        echo "<p><strong>Description:</strong> " . e($description) . "</p>";
        echo "</figcaption>";
        echo "</figure>";
        // Afficher le formulaire pour ajouter le livre aux favoris
        echo "<form method='post' action='bibliotheque.php' class= 'form'>";
        echo "<input type='hidden' name='bookId' value='" . e($bookId) . "'/>";
        echo "<button type='submit' name='favorite' class='btn btn-animate'>Ajouter aux favoris</button>";
        echo "</form>";

        echo "</article>";
        ?>
        <?php
        $similarBooks = get_similar_books($bookId, $data['volumeInfo'] ?? [], 3);
        echo "<article>";
        echo "<h3>Livres similaires</h3>";
        echo "<div class=\"book-grid\">";
        foreach ($similarBooks as $similarBook) {
            $similarInfo = isset($similarBook['volumeInfo']) && is_array($similarBook['volumeInfo']) ? $similarBook['volumeInfo'] : [];
            $similarTitle = trim((string) ($similarInfo['title'] ?? 'Titre non disponible'));
            $similarImage = $similarInfo['imageLinks']['thumbnail'] ?? 'images/book-placeholder.svg';
            $similarImage = str_replace('http://', 'https://', $similarImage);
            $similarAuthor = isset($similarInfo['authors']) && is_array($similarInfo['authors']) ? implode(", ", $similarInfo['authors']) : 'Auteur inconnu';
            $similarId = trim((string) ($similarBook['id'] ?? ''));
            $authorLink = 'data_auteur.php?authorName=' . rawurlencode(author_url_id($similarAuthor));

            echo "<figure>";
            echo "<a href=\"details.php?bookId=" . e($similarId) . "\">";
            echo "<img src=\"" . e($similarImage) . "\" alt=\"Couverture de " . e($similarTitle) . "\" class=\"cover\" title=\"" . e($similarTitle) . "\" loading=\"lazy\" onerror=\"this.onerror=null;this.src='images/book-placeholder.svg';\"/>";
            echo "</a>";
            echo "<figcaption>";
            echo "<p>Titre : <a href=\"details.php?bookId=" . e($similarId) . "\">" . e($similarTitle) . "</a></p>";
            echo "<p>Auteur : <a href=\"" . e($authorLink) . "\">" . e($similarAuthor) . "</a></p>";
            echo "</figcaption>";
            echo "</figure>";
        }
        echo "</div>";
        echo "</article>";
        ?>


        <div class="scroll">
            <i class="icofont-rounded-up"></i>
        </div>
    </main>

    <?php

    require("include/footer.inc.php");


    ?>
