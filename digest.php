<?php namespace kafene;

/**
 * Verify and require a valid HTTP Digest Auth login
 * users can be: array['name' => 'password',  'name2 => 'password'];
 * OR: array['name' => 'A1:{...}',  'name2 => 'A1:{...}'];
 * Where the {...} is md5($name.':'.$realm.':'.$password)
 * @param array $users in array(user => password) form
 * @param bool $HA1 - true if users are in the 2nd form.
 * @example if(\kafene\digest::check(array('admin'=>'pass'))) { echo 'hi!'; }
 * @todo need to check for stale nonce? qop=auth-int
 * @todo - brute force protection
   http://tools.ietf.org/html/rfc2617
 */

# if(digest::check(array('admin' => 'pas'))) { echo 'welcome!'; }

class digest {
  // All of these are public and can be overridden.
  static $realm,  $users,  $method,  $auth_header
  ,  $safe_mode_use_uid = true,  $prompt_callback
  , $forced_method,  $allow_method_override = true
  , $allow_request_auth = true, $allow_cookie_auth = true
  , $auth_digest,  $forced_auth_digest,  $digest_parsed
  , $parsedigest_callback  
  , $allowed_methods = array('GET', 'POST', 'HEAD', 'CONNECT')
  , $required = array('nonce','nc','cnonce','qop','username','uri','response');
  // Set the users / realm for use later
  static function setup(array $users = array(), $realm = null)
  {
    self::$realm = $realm
      ?: (getenv('SERVER_NAME')
      ?: 'SECURE');
    // safe mode.. yuck. it auto-appends uid to realm.
    if(ini_get('safe_mode') && $safe_mode_use_uid) {
      $uid = getmyuid();
      if($uid && substr($realm, -strlen($uid)) != $uid)
       self:: $realm .= '-'.$uid;
    }
    self::$users = $users;
  }
  // The main function here, the only one you ~need~ to call for this to work.
  static function check(array $users = array(), $realm = null)
  {
    if($users || $realm)
      self::setup($users, $realm);
    $users  = self::$users;
    $realm  = self::$realm;
    $digest = self::getAuthDigest();
    if(!$digest)
      return self::prompt();
    $res = self::parseDigest($digest);
    // prompt again if no user was received or user doesn't exist
    if(empty($res['username']) || empty($users[$res['username']]))
      return self::prompt();
    $user = $res['username'];
    $pass = $users[$res['username']];
    $A1   = self::getA1($user, $pass);
    $A2   = self::getA2($res['uri']);
    $mid  = array($res['nonce'], $res['nc'], $res['cnonce'], $res['qop']);
    $valid = sprintf('%s:%s:%s', $A1, implode(':',$mid), $A2);
    if($res['response'] === md5($valid))
      return $user;
    return self::prompt();
  }
  static function prompt()
  {
    if(is_callable(self::$prompt_callback))
      return call_user_func_array(self::$prompt_callback, func_get_args());
    // This is a new function in php 5.4
    if(function_exists('http_response_code')) http_response_code(401);
    // This is a workaround for older versions of php
    else header(':', true, 401);
    // Set authentication header
    self::$auth_header = $auth_header = 'WWW-Authenticate: '
    . 'Digest realm="%s", qop="auth", nonce="%s", opaque="%s"';
    // Send auth. header
    exit(header(
      sprintf($auth_header, self::$realm , uniqid('',true) , md5(self::$realm))
    ));
  }
  static function getA1($user, $pass, $realm = null)
  {
    if(!$realm) $realm = self::$realm;
    if(!$realm) return !trigger_error('Realm Not Found!');
    if(substr($user, 0, 3) === 'A1:')
      return substr($user, 3);
    return md5(sprintf('%s:%s:%s', $user, $realm, $pass));
  }
  static function getA2($uri, $method = null)
  {
    if(!$method) $method = self::getMethod();
    return md5(sprintf('%s:%s', $method, $uri));
  }
  static function getMethod()
  {
    if(!empty(self::$forced_method)) {
      self::$method = self::$forced_method;
      return self::$method;
    }
    if(getenv('REQUEST_METHOD'))
      self::$method = getenv('REQUEST_METHOD');
    elseif(!empty($_SERVER['REQUEST_METHOD']))
      self::$method = $_SERVER['REQUEST_METHOD'];
    if(self::$allow_method_override) {
      if(!empty($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
        $test = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'];
        if(in_array($test, self::$allowed_methods))
          self::$method = $test;
      } elseif(!empty($_POST['_method'])) {
        $test = $_POST['_method'];
        if(in_array($test, self::$allowed_methods))
          self::$method = $test;
      }
    }
    return self::$method;
  }
  # VVV THIS SUCKS
  static function getAuthDigest()
  {
    $res = null;
    if(!empty(self::$forced_auth_digest))
       $res = self::$forced_auth_digest;
    elseif(!empty($_SERVER['PHP_AUTH_DIGEST']))
           $res = $_SERVER['PHP_AUTH_DIGEST'];
    elseif(!empty($_SERVER['HTTP_AUTHORIZATION']))
           $res = $_SERVER['HTTP_AUTHORIZATION'];
    elseif(!empty($_SERVER['Authorization']))
           $res = $_SERVER['Authorization'];
    elseif(       getenv('PHP_AUTH_DIGEST'))
           $res = getenv('PHP_AUTH_DIGEST');
    elseif(       getenv('HTTP_AUTHORIZATION'))
           $res = getenv('HTTP_AUTHORIZATION');
    elseif(       getenv('Authorization'))
           $res = getenv('Authorization');
    //elseif(!empty($_REQUEST['auth']))
    //       $res = stripslashes(urldecode($_REQUEST['auth']));
    self::$auth_digest = $res;
    return $res;
  }
  static function parseDigest($digest)
  {
    if(is_callable(self::$parsedigest_callback))
      return call_user_func_array(self::$parsedigest_callback, func_get_args());
    // Match received params name ([1]) and value ([2])
    preg_match_all('#(\w+)="?([^",]+)"?#', $digest, $params_recd);
    foreach(self::$required as $required_param) {
      if(!in_array($required_param, $params_recd[1]))
        return self::prompt();
    }
    $res = array_combine($params_recd[1] + self::$required, $params_recd[2]);
    self::$digest_parsed = $res;
    return $res;
  }
}

