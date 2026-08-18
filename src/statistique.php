<?php
$des = "BookTopia - Statistiques";
$title = "Statistiques";
$h1 = "Statistiques";
$num ="L2";
require("include/header.inc.php");




?>




<main>
    <article>

        <h3>Les statistiques des livres</h3>
        <figure class="stats">
            <img src="graphLivre.php" alt="Histogramme des livres en fonction du nombre des visites" title="Histogramme des livres en fonction du nombre des visites" class="graph"/>
            <figcaption>Histogramme des livres les plus cliqués en fonction du nombre des visites</figcaption>
        </figure>
    </article>
    <article>
        <h3>Les statistiques des recherches</h3>
        <figure class="stats">
            <img src="graphRecherche.php" alt="Histogramme des recherches en fonction du nombre des visites" title="Histogramme des recherches en fonction du nombre des visites" class="graph"/>
            <figcaption>Histogramme des recherches en fonction du nombre de visites</figcaption>
        </figure>
    </article>
    <article>
        <h3>Les statistiques des auteurs</h3>
        <figure class="stats">
            <img src="graphAuteur.php" alt="Histogramme des auteurs en fonction du nombre des visites"  title="Histogramme des auteurs en fonction du nombre des visites" class="graph"/>
            <figcaption>Histogramme des auteurs les plus cliqués en fonction du nombre des visites</figcaption>
        </figure>
    </article>
    <article>
        <h3>Nombre de visite total du site</h3>
        <p><?php echo compteur(); ?></p>
    </article>
</main>

<div class="scroll">
    <i class="icofont-rounded-up"></i>
</div>

<?php
require("include/footer.inc.php");
?>
