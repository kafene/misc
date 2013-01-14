<?php

// github flavored markdown via api
function github_markdown($text) {
  $ch = curl_init('https://api.github.com/markdown/raw');
  curl_setopt_array($ch, array(\CURLOPT_POST => true
  , \CURLOPT_RETURNTRANSFER => true, \CURLOPT_POSTFIELDS => $text
  , \CURLOPT_SSL_VERIFYPEER => false, \CURLOPT_UNRESTRICTED_AUTH => true
  , CURLOPT_HTTPHEADER => array('Content-Type: text/plain')));
  $ret = curl_exec($ch); curl_close($ch); return $ret;
}
