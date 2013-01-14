<?php

/* Shorten a URL using Google's goo.gl API. Requires an API key. */
function shorten_url($url, $api_key){
  $endpoint = 'https://www.googleapis.com/urlshortener/v1';
  $ch = curl_init(sprintf('%s/url?key=%s', $endpoint, $api_key));
  curl_setopt_array($ch, array(\CURLOPT_POST => true
  , \CURLOPT_AUTOREFERER => true, \CURLOPT_FOLLOWLOCATION => true
  , \CURLOPT_UNRESTRICTED_AUTH => true, \CURLOPT_RETURNTRANSFER => true
  , \CURLOPT_HTTPHEADER => array('Content-Type: application/json')
  , \CURLOPT_POSTFIELDS => json_encode(array('longUrl' => $url))));
  $res = curl_exec($ch); curl_close($ch); return json_decode($res, true);
}
