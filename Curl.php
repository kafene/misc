<?php

class curl {
  const MOZ = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:20.0) '
            . 'Gecko/20121206 Firefox/20.0';
  const CHROME = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21'
               .  ' (KHTML, like Gecko) Chrome/25.0.1354.0 Safari/537.21';
  static $ua = self::CHROME, $cookies = array(), $timeout = 30, $jar = '';
  static function get($url) {
    $ch = self::setup($url);
    $res = curl_exec($ch);
    $out = array('info'=>curl_getinfo($ch), 'body'=>self::body($res));
    curl_close($ch);
    return $out;
  }
  static function post($url, $params) {
    $ch = self::setup($url, \CURLOPT_POST);
    $params = http_build_query($params,'&');
    curl_setopt($ch, \CURLOPT_POSTFIELDS, $params);
    $res = curl_exec($ch);
    $out = array('info'=>curl_getinfo($ch), 'body'=>self::body($res));
    curl_close($ch);
    return $out;
  }
  static function setup($url, $mode = \CURLOPT_HTTPGET) {
    $ch = curl_init();
    if(empty(self::$jar))
      self::$jar = tmpfile();
    if(!empty(self::$cookies))
      curl_setopt($ch, \CURLOPT_COOKIE, http_build_query(self::$cookies, ';'));
    curl_setopt($ch, $mode, true);
    curl_setopt($ch, \CURLOPT_URL, $url);
    curl_setopt($ch, \CURLOPT_COOKIEJAR, self::$jar);
    curl_setopt($ch, \CURLOPT_COOKIEFILE, self::$jar);
    curl_setopt($ch, \CURLOPT_CONNECTTIMEOUT, self::$timeout);
    curl_setopt($ch, \CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, \CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, \CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, \CURLOPT_USERAGENT, self::$ua);
    return $ch;
  }
  static function body($html) {
    if(!$html) return;
    $dom = $temp = new \DOMDocument();
    libxml_use_internal_errors(true);
    if($dom->loadHTML(mb_convert_encoding($html, 'UTF-8'))) {
      $body = $dom->getElementsByTagName('body');
      $body = $body->item(0)->getElementsByTagName('*')->item(0);
      $temp->appendChild($temp->importNode($body, true));
      $body = $temp->saveHTML();
      return $body;
    } else return null;
  }
}
