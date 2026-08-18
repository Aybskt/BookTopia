<?php
$des = 'Démonstrations techniques et APIs de BookTopia';
$title = 'Technologies - BookTopia';
$num = 'Dev web';
$h1 = 'Projet Dev Web';
require 'include/header.inc.php';

$config = booktopia_config();
$remoteIp = filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: '';
$isPublicIp = $remoteIp !== '' && filter_var($remoteIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
$nasaUrl = 'https://api.nasa.gov/planetary/apod?' . http_build_query(['api_key' => $config['nasa_key'] ?? 'DEMO_KEY'], '', '&', PHP_QUERY_RFC3986);
$nasa = api_get_json($nasaUrl);

$ip2Data = null;
$ipInfoData = null;
if ($isPublicIp) {
    $ip2Data = api_get_json('https://api.ip2location.io/?' . http_build_query(['key' => $config['ip2location_key'] ?? '', 'ip' => $remoteIp], '', '&', PHP_QUERY_RFC3986));
    $ipInfoData = api_get_json('https://ipinfo.io/' . rawurlencode($remoteIp) . '/json?' . http_build_query(['token' => $config['ipinfo_token'] ?? ''], '', '&', PHP_QUERY_RFC3986));
}
?>
<main>
    <article>
        <h3>L’image du jour de la NASA</h3>
        <?php if (is_array($nasa) && ($nasa['media_type'] ?? '') === 'image' && !empty($nasa['url'])) : ?>
            <figure class="nasa" id="nasa">
                <img alt="<?php echo e($nasa['title'] ?? 'Image du jour de la NASA'); ?>" title="<?php echo e($nasa['title'] ?? 'Image du jour de la NASA'); ?>" src="<?php echo e($nasa['url']); ?>" class="image" />
                <figcaption><?php echo e($nasa['title'] ?? 'Image du jour de la NASA'); ?></figcaption>
            </figure>
        <?php elseif (is_array($nasa) && ($nasa['media_type'] ?? '') === 'video' && !empty($nasa['url'])) : ?>
            <figure class="nasa">
                <iframe width="560" height="315" src="<?php echo e($nasa['url']); ?>" title="<?php echo e($nasa['title'] ?? 'Vidéo du jour de la NASA'); ?>" loading="lazy" allowfullscreen></iframe>
                <figcaption><?php echo e($nasa['title'] ?? 'Vidéo du jour de la NASA'); ?></figcaption>
            </figure>
        <?php else : ?>
            <p>L’image du jour est temporairement indisponible.</p>
        <?php endif; ?>
    </article>

    <article id="g">
        <h3>Votre localisation réseau avec IP2Location</h3>
        <?php if (!$isPublicIp) : ?>
            <p>La géolocalisation n’est pas disponible depuis une adresse locale.</p>
        <?php elseif (!is_array($ip2Data)) : ?>
            <p>Le service de localisation est temporairement indisponible.</p>
        <?php else : ?>
            <ul>
                <?php
                $ip2Fields = [
                    'ip' => 'Adresse IP', 'as' => 'Réseau', 'asn' => 'ASN', 'city_name' => 'Ville',
                    'region_name' => 'Région', 'country_name' => 'Pays', 'zip_code' => 'Code postal', 'time_zone' => 'Fuseau horaire',
                ];
                foreach ($ip2Fields as $field => $label) {
                    if (!empty($ip2Data[$field])) echo '<li>' . e($label) . ' : ' . e($ip2Data[$field]) . '</li>';
                }
                if (isset($ip2Data['latitude'], $ip2Data['longitude'])) echo '<li>Coordonnées : ' . e($ip2Data['latitude']) . ' | ' . e($ip2Data['longitude']) . '</li>';
                ?>
            </ul>
        <?php endif; ?>
    </article>

    <article id="ip">
        <h3>Informations réseau avec IPinfo</h3>
        <?php if (!$isPublicIp) : ?>
            <p>Les informations réseau ne sont pas disponibles depuis une adresse locale.</p>
        <?php elseif (!is_array($ipInfoData)) : ?>
            <p>Le service réseau est temporairement indisponible.</p>
        <?php else : ?>
            <ul>
                <?php
                $ipInfoFields = ['ip' => 'Adresse IP', 'hostname' => 'Nom d’hôte', 'city' => 'Ville', 'region' => 'Région', 'country' => 'Pays', 'loc' => 'Coordonnées', 'postal' => 'Code postal', 'timezone' => 'Fuseau horaire'];
                foreach ($ipInfoFields as $field => $label) {
                    if (!empty($ipInfoData[$field])) echo '<li>' . e($label) . ' : ' . e($ipInfoData[$field]) . '</li>';
                }
                ?>
            </ul>
        <?php endif; ?>
    </article>
    <div class="scroll"><i class="icofont-rounded-up"></i></div>
</main>
<?php require 'include/footer.inc.php'; ?>
