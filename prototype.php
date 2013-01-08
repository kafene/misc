<?php

# http://joshosopher.tumblr.com/post/17295179484/php-5-4-traits-closures-and-prototype-based
# A class for prototype based programming (ala javascript)
/*
$thing = new prototype;
$thing->dostuff = function() { echo 'hello!'; };
$thing->bla = function() { return 3; };
$thing->dostuff();
var_dump($thing->bla());
# */

class prototype {
  private  $p=[], $m=[];
  function &__get($k) {
    if(array_key_exists($k,$this->p)) return $this->p[$k];
    elseif(array_key_exists($k,$this->m)) return $this->m[$k];
  }
  function __set($k,$v) {
    if(is_object($v) && is_callable($v)) {
      if(!array_key_exists($k,$this->m)) $this->m[$k] = [];
      if($v instanceof \Closure) $v = $v->bindTo($this);
      $this->m[$k][] = $v;
    } else $this->p[$k] = $v;
  }
  function __call($k,$args=[]) {
    if(array_key_exists($k,$this->m) && ($mx = $this->m[$k]))
      if(is_array($mx)) foreach($mx as $m)
        if(!is_null($res = call_user_func_array($m,$args))) return $res;
  }
}
