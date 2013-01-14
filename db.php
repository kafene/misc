<?php

class db {
  var $pdo = null, $pk = 'id';
  static $log = array();
  // @todo - get($column, $where) ?
  function __construct(\PDO $pdo, $pk = 'id') {
    $this->pdo = $pdo; $this->pk = $pk;
    $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    return $this->pdo;
  }
  function query($query, $params = null) {
    if(!$params) return $this->pdo->query(static::$log[] = $query);
    $st = $this->pdo->prepare(static::$log[] = $query);
    return $st->execute((array)$params) ? $st : false;
  }
  function insert($table, array $data, array $keys_allowed = array()) {
    if(!empty($keys_allowed)) $data = array_intersect_key($data,$keys_allowed);
    if(empty($data)) return;
    return $this->query('REPLACE INTO '.$this->pdo->quote($table).' (`'
    . implode('`,`',array_keys($data)).'`) VALUES ('.rtrim(str_repeat('?,'
    , count($data = array_values($data))), ',').')', $data)
    ? ($this->pdo->inTransaction()? true : $this->pdo->lastInsertId()) : false;
  }
  function delete($table, $val) {
    if($st = $this->query('DELETE FROM `'.$table.'` WHERE `'.$this->pk.'`=?'
    , $val)) return $this->pdo->inTransaction() ? true : $st->rowCount();
  }
  static function params(array $params, $t = '`') {
    foreach($params as $k => $v) $params[$k] = trim($v);
    $out = array('SET' => '', 'RES' => array());
    $out['COL'] = $t.implode($t.', '.$t, array_keys($params)).$t;
    $out['VAL'] = substr(str_repeat('?, ', count($params)), 0, -2);
    $out['INS'] = ':'.implode(', :',array_keys($params));
    foreach($params as $k => $v) $out['SET'] .= $k.' = :'.$k.', ';
    $out['SET'] = rtrim($out['SET'], ',');
    foreach($params as $k => $v) $out['RES'][':'.$k] = $v;
    return $out;
  }
}
