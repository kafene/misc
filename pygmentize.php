<?php

function pygmentize($lang, $code) {
  $css = 'https://kafene.github.com/asset/misc/pygments.css';
  $lang = urlencode($lang);
  $code = urlencode($code);
  $ch = curl_init();
  curl_setopt_array($ch, array(
    \CURLOPT_URL => 'http://pygments.appspot.com/'
  , \CURLOPT_POST => 2
  , \CURLOPT_RETURNTRANSFER => 1
  , \CURLOPT_POSTFIELDS => sprintf('lang=%s&code=%s', $lang, $code)
  ));
  $res = curl_exec($ch);
  curl_close($ch);
  return array('html' => $res, 'css' => $css);
}
