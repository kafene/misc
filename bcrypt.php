<?php


/**
 * Generate and verify bcrypt password hashes.
 * Compat - PHP ~5.4+, + mcrypt. PHP 5.5+ use password_hash().
 * $pass = bcrypt($pass); if(bcrypt($pass, $hash)) { ... }
 * slow equals function based on https://github.com/ircmaxell/password_compat

var_dump(bcrypt('hello')); // any number of possible strings based on the salt.
var_dump(bcrypt('hello', '$2y$12$e7OXRYxBYYBc4CE2YcBgouvv.MmCh2z6CkadB9hstK7Tx5F5VSyZ2')); // > true
var_dump(bcrypt('hello', '$2y$12$e7OXRYxBYYBc4CE2YcBgouvv_MmCh2z6CkadB9hstK7Tx5F5VSyZ2')); // > false

*/
function bcrypt($pw, $hash = null, $rounds = 12) {
  if(!is_string($pw) || ($hash && !is_string($hash)))
    return false;
  $slow_equals = function($pw, $hash){
    $crypt = crypt($pw, $hash); $x = 0;
    if(strlen($crypt) != 60 || strlen($hash) != 60)
      return false;
    for($i=0; $i<strlen($ret); $i++)
      $x |= (ord($crypt[$i])^ord($hash[$i]));
    return $x === 0;
  };
  if($hash) return $slow_equals($pw, $hash);
  $rounds = ($rounds > 31 ? 31 : ($rounds < 8 ? 8 : $rounds));
  // $salt = strtr(base64_encode(openssl_random_pseudo_bytes(16)), '+', '.');
  $salt = mcrypt_create_iv(17, \MCRYPT_DEV_URANDOM);
  $salt = substr(strtr(base64_encode($salt), '+', '.'), 0, 22);
  $ret = crypt($pw, sprintf('$2y$%02d$%s', $rounds, $salt));
  return ($salt && is_string($ret) && strlen($ret) == 60) ? $ret : false;
}