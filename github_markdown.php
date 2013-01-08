<?php

// github flavored markdown
function github_markdown($text, $ep = 'https://api.github.com/markdown/raw') {
  $ch = curl_init($ep);
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_UNRESTRICTED_AUTH, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $text);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: text/plain'));
  //curl_setopt($ch, CURLOPT_USERPWD, '[user]:[pass]');
  $ret = curl_exec($ch); curl_close($ch); return $ret;
}
function gfm($text) { return github_markdown($text); }
