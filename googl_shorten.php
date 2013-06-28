<?php

# Shorten a URL using Google's goo.gl API. Requires an API key.
function googl_shorten($url, $api_key, $endpoint = null) {
    $endpoint = $endpoint ?: 'https://www.googleapis.com/urlshortener/v1';
    $ch = curl_init(sprintf('%s/url?key=%s', $endpoint, $api_key));
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_AUTOREFERER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode(['longUrl' => $url]),
    ]);
    $result = curl_exec($ch);
    curl_close($ch);
    return json_decode($result);
}
