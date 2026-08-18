<?php
//  TD7
define("DEFAULT_LANGUAGE", "fr");


function date_et_heure($lang = 'fr')
{
    $months_fr = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];
    $months_en = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
    $days_fr = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];
    $days_en = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

    $today = new DateTime();
    $day = $today->format('d');
    $month = ($lang == 'en') ? $months_en[intval($today->format('m')) - 1] : $months_fr[intval($today->format('m')) - 1];
    $year = $today->format('Y');
    $day_of_week = ($lang == 'en') ? $days_en[intval($today->format('w'))] : $days_fr[intval($today->format('w'))];

    if ($lang == 'en') {
        return $day_of_week . ', ' . $month . ' ' . $day . ', ' . $year;
    } else {
        return $day_of_week . ' ' . $day . ' ' . $month . ' ' . $year;
    }
}



function get_navigateur()
{
    $nav = "";
    $user_agent = $_SERVER['HTTP_USER_AGENT'];

    switch (true) {
        case strpos($user_agent, 'Firefox') !== false:
            $nav = 'Mozilla Firefox';
            break;
        case strpos($user_agent, 'Chrome') !== false:
            $nav = 'Google Chrome';
            break;
        case strpos($user_agent, 'Safari') !== false:
            $nav = 'Apple Safari';
            break;
        case strpos($user_agent, 'Opera') || strpos($user_agent, 'OPR/'):
            $nav = 'Opera';
            break;
        case strpos($user_agent, 'Edge') !== false:
            $nav = 'Microsoft Edge';
            break;
        default:
            $nav = 'Navigateur inconnu';
            break;
    }

    return $nav;
}
