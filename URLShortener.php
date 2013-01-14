<?php

# URLShortener();
function URLShortener() { // 
  $href = getenv('SCRIPT_NAME').'?go=';
  $table = 'shortened';
  $getdb = function() use(&$getdb,$table) {
    static $dbc = null;
    if($dbc !== null) return $dbc;
    $db = new \PDO('sqlite:shorten.db');
    $db->query('CREATE TABLE IF NOT EXISTS `'.$table.'` (
      id INTEGER PRIMARY KEY, long TEXT UNIQUE, date INTEGER, by TEXT)');
    $dbc = $db;
    return $getdb();
  };
  $shorten = function($url) use($getdb, $table, $href) {
    if(false === filter_var($url, FILTER_VALIDATE_URL))
      throw new \Exception('Invalid URL');
    $db = $getdb();
    $test = $db->prepare('SELECT id FROM `'.$table.'` WHERE long = ? LIMIT 1');
    $test->execute(array($url));
    $test = $test->fetchColumn();
    if($test) {
      $url = strtolower(base_convert($test, 10, 36));
    } else {
      $st = $db->prepare('INSERT INTO `'.$table
      . '` (long,date,by) VALUES (?,?,?)');
      $st->execute(array($url, time(), $_SERVER['REMOTE_ADDR']));
      $url = strtolower(base_convert($db->lastInsertId(), 10, 36));
    }
    die('<a href="'.$href.$url.'">'.$href.$url.'</a>');
  };
  $redirect = function($id) use($getdb, $table) {
    if(preg_match('/[^a-z0-9]/', $id))
      die('Invalid ID');
    $db = $getdb();
    $long = $db->prepare('SELECT long FROM `'.$table.'` WHERE id = ? LIMIT 1');
    $long->execute(array(base_convert(strtolower($id), 36, 10)));
    $long = $long->fetchColumn();
    if(!$long) die('no link found');
    header('HTTP/1.1 301 Moved Permanently');
    exit(header('Location: '.$long));
  };
  if(!empty($_POST['url']))
    $shorten($_POST['url']);
  elseif(!empty($_GET['go']))
    $redirect($_GET['go']);
  else
    echo '<form method="post" action="" id="shortener">
    <input type="url" name="url" id="long">
    <input type="submit" value="Shorten"></form>';
}
