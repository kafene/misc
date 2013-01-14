<?php namespace kafene;

/*
__capt__ (capt. hook, get it?)

its very simple.  
its a static class that holds events and callback functions.  
you can hook an event, fire an event and unhook an event.

```php
capt::hook('a', function(){ echo 'a'; });
capt::hook('b', $b = function(){ echo 'b, '; });
capt::hook('b', function(){ echo 'b2'; });
capt::fire('a');
// -> prints 'a'
capt::fire('b');
// -> prints 'b, b2'
capt::unhook('b', $b);
capt::fire('b');
// -> now prints 'b2'
capt::unhook('b');
capt::fire('b');
// -> now prints ''
capt::hook('c', function($c, $d){ echo $c.$d; });
capt::fire('c', 'c, ', 'd'); // 'c, d'
// -> prints 'c, d'
capt::hook('e', function($e, $e2){ capt::unhook('e'); echo $e.$e2; });
capt::fire('e', 'e, ', 'e2');
// -> prints 'e', 'e2'
capt::fire('e', 'e, ', 'e2');
// -> now prints ''
```

... test ...

capt::hook('a', function(){ echo 'a<br>'; });
capt::hook('b', $b = function(){ echo 'b, '; });
capt::hook('b', function(){ echo 'b2<br>'; });
echo 'a<br>'; capt::fire('a'); echo '<hr>';
echo 'b, b2<br> '; capt::fire('b'); echo '<hr>';
capt::unhook('b', $b);
echo 'b2<br>'; capt::fire('b'); echo '<hr>';
capt::unhook('b');
echo ''; capt::fire('b'); echo '<hr>';
capt::hook('c', function($c, $d){ echo $c.$d; });
echo 'c, d<br>'; capt::fire('c', 'c, ', 'd<br>'); echo '<hr>';
capt::hook('e', function($e, $e2){ capt::unhook('e'); echo $e.$e2.'<br>'; });
echo 'e, e2<br>'; capt::fire('e', 'e, ', 'e2'); echo '<hr>';
echo ''; capt::fire('e', 'e, ', 'e2'); echo '<hr>';

# */

class capt {
  static $hooks = array();
  static function hook($e, callable $fn) {
    if(!isset(static::$hooks[$e]))
      static::$hooks[$e] = array();
    static::$hooks[$e][] = $fn;
  }
  static function unhook($e, callable $fn = null) {
    if(!$fn) unset(static::$hooks[$e]);
    elseif(false !== ($i = array_search($fn
    , static::$hooks[$e], true)))
      unset(static::$hooks[$e][$i]);
  }
  static function fire($e = null) {
    if(count(func_get_args()) > 1)
      $args = array_slice(func_get_args(), 1);
    foreach(array_key_exists($e, static::$hooks)
    ? static::$hooks[$e] : array() as $fn)
      return call_user_func_array($fn, $args);
  }
}
