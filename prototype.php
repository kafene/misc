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
  private $_props = [], $_methods = [];
  function &__get($name) {
      if(array_key_exists($name, $this->_props)) {
        return $this->_props[$name];
      } elseif(array_key_exists( $name, $this->_methods)) {
        return $this->_methods[$name];
      }
  }
  function __set($name, $value) {
    if(is_object($value) && is_callable($value)) {
      if(!array_key_exists($name, $this->_methods))
        $this->_methods[$name] = array();
      if($value instanceof \Closure)
        $value = $value->bindTo($this);
      $this->_methods[$name][] = $value;
    } else {
      $this->_props[$name] = $value;
    }
  }
  function __call($name, $args = []) {
    if(array_key_exists($name, $this->_methods)) {
      $methods = $this->_methods[$name];
      if(is_array($methods)) foreach($methods as $method) {
        if(null !== ($res = call_user_func_array($method, $args)))
          return $res;
      }
    }
  }
}
