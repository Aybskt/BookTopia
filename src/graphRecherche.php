<?php
DEFINE('USING_UTF8', true);
require_once __DIR__ . "/include/functions.inc.php";
// Charger la bibliothèque jpgraph
require_once("jpgraph/src/jpgraph.php");
require_once("jpgraph/src/jpgraph_bar.php");

// Lire les données du fichier CSV
$data = array();
$fichier = @fopen(project_storage_path('dataRecherche.csv'), "r");
while ($fichier !== false && ($ligne = fgetcsv($fichier)) !== false) {
    if (count($ligne) < 2) continue;
    $date = strtotime($ligne[0]);
    $nomLivre = $ligne[1];
    if (isset($data[$nomLivre])) {
        $data[$nomLivre]++;
    } else {
        $data[$nomLivre] = 1;
    }
}
if ($fichier !== false) fclose($fichier);

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
    $graph->title->Set("Les recherches les plus effectuées");
    $graph->xaxis->SetTitle("Recherches");
    $graph->yaxis->SetTitle("Nombre de fois");

    // Ajouter les données au graphique
    $bar = new BarPlot(array_values($data));
    $bar->SetFillGradient('#4DA0B0', '#D39D38', GRAD_HOR);
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
