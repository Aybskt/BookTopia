<?php
DEFINE('USING_UTF8', true);
require_once __DIR__ . "/include/functions.inc.php";
// Charger la bibliothèque jpgraph
require_once("jpgraph/src/jpgraph.php");
require_once("jpgraph/src/jpgraph_bar.php");

// Lire les données du fichier CSV
$data = array();
$fichier2 = @fopen(project_storage_path('dataLivre.csv'), "r");
while ($fichier2 !== false && ($ligne = fgetcsv($fichier2)) !== false) {
    if (count($ligne) < 3) continue;
    $date = strtotime($ligne[0]);
    $title_Book = $ligne[2];
    if (isset($data[$title_Book])) {
        $data[$title_Book]++;
    } else {
        $data[$title_Book] = 1;
    }
}
if ($fichier2 !== false) fclose($fichier2);

// Trier les données par ordre décroissant de fréquence
arsort($data);

// Sélectionner les 4 recherches les plus fréquentes
$data = array_slice($data, 0, 4);

// Vérifier si $data est vide
if (empty($data)) {
    // Si $data est vide, afficher un message et ne pas dessiner le graphique
    echo "Aucune donnée disponible";
} else {
    // Créer un graphique à barres
    $graph = new Graph(800, 500);
    $graph->SetScale("textlin");
    $graph->SetShadow();
    $graph->img->SetMargin(60, 30, 20, 100);
    $graph->title->Set("Les livres les plus cliqués");
    $graph->xaxis->SetTitle("Livres");
    $graph->yaxis->SetTitle("Nombre de fois");




    // Ajouter les données au graphique
    $bar = new BarPlot(array_values($data));
    $bar->SetFillGradient('#f0c27b', '#4b1248', GRAD_HOR);
    $bar->SetColor('transparent');
    $bar->value->SetFont(FF_DV_SANSSERIF, FS_BOLD, 12);
    $bar->value->SetColor("black");
    $bar->value->Show();


    // Ajouter les étiquettes des barres
    $graph->xaxis->SetTickLabels(array_keys($data));
    $graph->xaxis->SetFont(FF_DV_SANSSERIF, FS_NORMAL, 8);

    // Ajouter le graphique à l'image
    $graph->Add($bar);

    // Afficher le graphique
    $graph->Stroke();
}
