<?php namespace kafene;

/**
 * Library of functions/classes I am using right now.
 * I am working it into some kind of framework or something.
 * Still needs some documentation. Tried to write self-documenting code.
 * unless there's a citation for someone else (a link, copyright, etc),
 * any code here is mine and I release it under the following license:
 *
 * COPYRIGHT (c) 2013 kafene.org <http://kafene.org/COPYING>
 *
 * You may do anything with this work that any copyright law would normally
 * restrict, so long as you retain the above notice in all redistributed copies
 * and/or derived works. The works are provided `as-is` with no form of warranty.
 *
 * @todo - need to document a lot of stuff
 */

// This is the only function called when this script is included:
defaults();

echo '<pre>';
var_export(get_defined_constants());

// #############################################################################
// BASE FUNCTIONS ##############################################################
// #############################################################################

function defaults() {
  setup_defines();
  setup_base_options();
  capture_errors_into_exceptions();
  fix_globals();
  fix_https();
  fix_request();
  register_default_headers();
  encrypted_cookie_session_start();
  set_global_getters();
  // Doing these things allows, for example:
  // echo 'stuff!'; $_SESSION['stuff'] = 'more stuff';
  // without getting a 'headers already sent' message
  // as the output buffer will hold output until after
  // headers are sent, and response_send() will flush it.
  register_shutdown_function(__NAMESPACE__ .'\response_send');
  ob_start();
}

// Shortcut isset/get value or default
function v(&$v, $def = null) {
  return isset($v) ? $v : $def;
}

// Shortcut define or get constant if defined
function def($k, $v = null) {
  if(null === $v) return defined($k) ? constant($k) : false;
  elseif(!defined($k)) define($k, $v);
}

// Shortcut get from $_SERVER/$_ENV/getenv
function env($key = null) {
  static $env = null;
  if(!$env) $env = $_SERVER + $_ENV;
  if(!$key) return $env;
  return v($env[$key], (getenv($key) ?: null));
}

// Shortcut get from $_REQUEST/POST/GET
function req($key = null) {
  $method = request_method();
  switch($method) {
    case 'GET':    $test = array('_GET','_POST','_REQUEST'); break;
    case 'POST':   $test = array('_POST','_GET','_REQUEST'); break;
    case 'PUT':    $test = array('_REQUEST','_POST','_GET'); break;
    case 'DELETE': $test = array('_REQUEST','_POST','_GET'); break;
    default:       $test = array('_GET','_POST','_REQUEST'); break;
  }
  foreach($test as $r)
    if(isset($GLOBALS[$r][$key]));
      return $GLOBALS[$r][$key];
}

// Simple option holder - set/get/get all
function c($k = null, $v = null) {
  static $c = array();
  if($k === null && $v === null) return $c;
  if($v === null) return v($c[$k]);
  elseif($k) $c[$k] = $v;
}

/**
 * Event holder/emitter
ev('add', function($num){ return $num + 1; });
$i = 0; $i = ev('add',$i); $i = ev('add',$i);
ev('add',false); $i = ev('add',$i); var_dump($i); // > 2
*/
function ev($e, $v = null) {
  static $hooks;
  if($v === false) unset($hooks[$e]);
  elseif(is_callable($v)) $hooks[$e][] = $v;
  elseif(isset($hooks[$e])) {
    foreach($hooks[$e] as $f)
      $v = call_user_func_array($f, array_slice(func_get_args(), 1));
    return $v;
  } else return $v;
}

// String sanitizer
function h($str) {
  $flags = \FILTER_FLAG_STRIP_LOW | \FILTER_FLAG_STRIP_HIGH;
  // $str = filter_var($str, \FILTER_SANITIZE_STRING, $flags);
  $str = preg_replace('/\p{C}+/u', '', $str); // strip control chars
  $flags = \ENT_HTML5 | \ENT_QUOTES | \ENT_SUBSTITUTE | \ENT_DISALLOWED;
  return htmlentities($str, $flags, 'UTF-8', false);
}

// Get a formatted log entry. Doesn't write anything.
function log_line($msg, $args = null, $level = 'DEBUG') {
  $mode = defined($level) ? constant($level) : $level;
  $line = "[".gmdate('c')."] $mode\n$msg\n";
  if($args !== null) $line .= serialize($args)."\n";
  return $line.str_repeat('=', 80)."\n\n";
  // $file = defined('ERROR_LOGFILE') ? ERROR_LOGFILE : false;
  // error_log($line, $file ? 3 : 0, $file ?: null);
}

// #############################################################################
// SETUP FUNCTIONS #############################################################
// #############################################################################

function fix_https() {
  if(!isset($_SERVER['HTTPS']) || strtolower($_SERVER['HTTPS']) == 'off')
    $_SERVER['HTTPS'] = null;
}

// Add php://input to request, e.g. for DELETE and PUT methods
// treated with last priority - eg any existing $_REQUEST value
// will remain, only values unique to php://input are inserted.
// Also parses the QUERY_STRING into $_GET in the same manner.
function fix_request() {
  parse_str(file_get_contents('php://input'), $_ta);
  $_REQUEST = array_merge((array)$_ta, $_REQUEST);
  parse_str(v($_SERVER['QUERY_STRING']), $_tb);
  $_REQUEST = array_merge((array)$_tb, $_REQUEST);
}

function fix_globals() {
  $g = array('_SERVER', '_FILES',' _REQUEST', '_SESSION', '_ENV', '_COOKIE');
  foreach($g as $key)
    if(empty($GLOBALS[$key]) && isset(${$key}))
      $GLOBALS[$key] =& ${$key};
}

// Sets _* (lowercase) to get from session, get, post, env, etc.
function set_global_getters() {
  foreach(array('SESSION','GET','POST','ENV'
  ,'SERVER','COOKIE','FILES','REQUEST') as $V)
  eval('if(!function_exists("_'.strtolower($V).'")) {
    function _'.strtolower($V).'($k, $d = null) {
      return isset($_'.$V.'[$k]) ? $_'.$V.'[$k] : $d;
    }
  }');
}

function capture_errors_into_exceptions() {
  set_exception_handler($ex = function(\Exception $e){
    if(ini_get('log_errors'))
      error_log(log_line($e->getMessage(),$e->getTraceAsString(),$e->getCode()));
    $msg = sprintf('<h1>Error</h1><h3>%s (%s)</h3><pre>%s</pre>'
    , $e->getMessage(), $e->getCode(), $e->getTraceAsString());
    try {
      response::$status = 500;
      ob_clean(); ob_start();
      echo $msg; response_send();
    } catch(\Exception $ex) { exit($msg); }
  });
  set_error_handler(function($n,$s,$f,$l) use($ex){
    if($n & error_reporting())
      $ex(new \ErrorException($s, $n, 0, $f, $l));
  });
}

function register_default_headers($expires = '+33 Days', $keep_alive = false, $cors = false) {
  header_register_callback(function() use($expires, $cors, $keep_alive){
    $exp = $expires === false ? time()-(3600*24*30) : strtotime($expires, 0);
    header('Content-Type: text/html; charset=utf-8', false);
    header('Cache-Control: max-age='.$exp, false);
    header('Cache-Control: no-transform', false);
    header('X-UA-Compatible: IE=Edge,chrome=1', true);
    header('Expires: '.gmdate('D, d M Y H:i:s \G\M\T', time()+$exp), false);
    header('Last-Modified: '.gmdate('D, d M Y H:i:s \G\M\T', time()-$exp), false);
    header('Pragma: Public', false); # or Pragma: no-cache
    if($cors) header('Access-Control-Allow-Origin: *', true); // enable-cors.org
    if($keep_alive) header('Connection: Keep-Alive', false);
    else header('Connection: Close', false);
  });
}

function setup_defines() {
  def('___TIME__START', microtime(true));
  def('ENCRYPTION_KEY', get_encryption_key());
  def('X-SENDFILE', 10);
  def('X-LIGHTTPD-SEND-FILE', 20);
  def('E_DEPRECATED', 8192);
  def('E_USER_DEPRECATED', 16384);
  def('E_RECOVERABLE_ERROR', 4096);
  def('PASSWORD_BCRYPT', 1);
  def('PASSWORD_DEFAULT', PASSWORD_BCRYPT);
  def('MCRYPT_MODE_CBC', 'cbc');
  def('MCRYPT_RIJNDAEL_256', 'rijndael-256');
  def('MCRYPT_MARS', 'mars');
  def('COOKIE_DEFAULT_EXPIRE', 2851200); // 33 days
  def('COOKIE_FLAG_COOKIE_SEND', 'COOKIE_FLAG_COOKIE_SEND');
  def('DS', \DIRECTORY_SEPARATOR);
  def('NL', \PHP_EOL);
}

function setup_base_options() {
  date_default_timezone_set('GMT');
  ini_set('date.timezone', 'GMT');
  ini_set('date.default_latitude', '45.0');
  ini_set('date.default_longitude', '-71.526451');
  ini_set('magic_quotes_runtime', 0);
  ini_set('default_socket_timeout', 10);
  iconv_set_encoding('internal_encoding', 'UTF-8');
  iconv_set_encoding('output_encoding', 'UTF-8');
  iconv_set_encoding('input_encoding', 'UTF-8');
  mb_internal_encoding('UTF-8');
  ini_set('mbstring.language', 'neutral');
  ini_set('mbstring.http_input', 'UTF-8');
  ini_set('mbstring.http_output', 'UTF-8');
  ini_set('mbstring.strict_detection', 1);
  ini_set('default_charset', 'UTF-8');
  ini_set('auto_detect_line_endings', 1);
  libxml_use_internal_errors(true);
  ini_set('zlib.output_compression', 1);
  ini_set('zlib.output_compression_level', -1);
  ini_set('arg_separator.output', '&amp;');
  ini_set('arg_separator.input', ';&');
  ini_set('implicit_flush', 0);
  assert_options(\ASSERT_ACTIVE, 1);
  // assert_options(\ASSERT_QUIET_EVAL, 1);
  assert_options(\ASSERT_WARNING, 1);
  /**/
  ini_set('allow_url_include', 1);
  ini_set('cgi.rfc2616_headers', 1);
  ini_set('memory_limit', '16M');
  ini_set('max_execution_time', 15);
  // ini_set('xbithack', 1);
  // ini_set('last_modified', 0);
  // ini_set('zend.script_encoding', 'utf-8');
  /**/
  ini_set('default_mimetype', 'text/html');
  ini_set('user_agent', 'kafene.lib_kafene');
  c('kafene.key', def('ENCRYPTION_KEY'));
  c('kafene.cookie_expire', COOKIE_DEFAULT_EXPIRE);
  c('kafene.sid', 'kafene.session');
}

// @todo allow customization
function setup_max_errors() {
  ini_set('display_errors', 1);
  ini_set('error_reporting', -1);
  error_reporting(-1);
  ini_set('report_zend_debug', 1);
  ini_set('report_memleaks', 1);
  ini_set('log_errors', 0);
  ini_set('track_errors', 1);
  ini_set('html_errors', 1);
  ini_set('xdebug.scream', 1);
  ini_set('display_startup_errors', 1);
  ini_set('docref_root', 'http://us1.php.net/manual/en/');
  ini_set('docref_ext', '.php');
  ini_set('ignore_user_abort', 0);
  ini_set('ignore_repeated_source', 0);
  ini_set('ignore_repeated_errors', 0);
  ini_set('windows_show_crt_warning', 1);
  ini_set('error_log', 'kafene_errors.log');
  ini_set('log_errors_max_len', 2097152); // 2mb
}

function session_started() {
  return session_status() == \PHP_SESSION_ACTIVE;
}

// #############################################################################
// REQUEST HANDLING FUNCTIONS ##################################################
// #############################################################################

/**
 * Check if client accepts a mime type
 * Assumes empty/missing accept header means "all" for compatibility
 * @param string $mime - a mime type to check the HTTP_ACCEPT header for
 * @return bool
 */
function client_accepts($mime) {
  if(empty($_SERVER['HTTP_ACCEPT'])) return true;
  $accept = trim($_SERVER['HTTP_ACCEPT']);
  if(!$accept) return true; // idk, if it was a space or something.
  $list = explode(',', $accept);
  foreach($list as $item) {
    $item = trim($item);
    sscanf($item, '%[^;]', $client_mime);
    if($mime == trim($client_mime)) return true;
    elseif($client_mime == '*/*') return true;
  }
  return false;
}

/**
 * Get the current request method
 * @param bool $allow_override - whether to allow method overrides
 * @return string
 */
function request_method($allow_override = true) {
  if($allow_override) {
    if(isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']))
      return $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'];
    if(isset($_POST['_method']))
      return $_POST['_method'];
  }
  return env('REQUEST_METHOD') ?: 'GET';
}

// Check if $url is on current host or $host
function url_on_host($url, $host = null) {
  if(false === $url_host = parse_url($url, \PHP_URL_HOST)) return false;
  if(strcasecmp($url_host, (getenv('SERVER_NAME') ?: -1)) === 0) return true;
  if(strcasecmp($url_host, (get_server_ip() ?: -1)) === 0) return true;
  return false;
}

// http://stackoverflow.com/questions/5705082/is-serverserver-addr-safe-to-rely-on
// @todo - what about 192.168 address? or if server has multiple IPs?
function server_ip() {
  if(isset($_SERVER['SERVER_ADDR']))
    return $_SERVER['SERVER_ADDR'];
  if(isset($_SERVER['LOCAL_ADDR']))
    return $_SERVER['LOCAL_ADDR'];
  if(isset($_SERVER['SERVER_NAME']))
    return gethostbyname($_SERVER['SERVER_NAME']);
  if(stristr(\PHP_OS, 'WIN'))
    return gethostbyname(php_uname('n'));
  preg_match('/addr:([\d\.]+)/', `ifconfig eth0`, $m);
  return isset($m[1]) ? trim($m[1]) : '127.0.0.1';
}

// @todo - what about multiple hostnames?
function server_name($default = 'localhost') {
  if(!empty($_SERVER['SERVER_NAME']))
     return $_SERVER['SERVER_NAME'];
  if(stristr(\PHP_OS, 'WIN'))
    // This should be fast since the DNS lookup will be local.
    return gethostbyaddr(server_ip()) ?: $default;
  return trim(`hostname`) ?: $default;
}

/**
 * Get the current url
 * doesn't support getting the query string right now
 * you can maybe do current_url().getenv('QUERY_STRING') for that
 * @param bool $host - whether to include http://whatever.ext in result
 * @param bool $path - whether to include /path/to in result
 * @param bool $file - whether to include /?filename.
 * @return string
 */
function current_url($host = true, $path = true, $file = true) {
  static $_cached = array();
  if(!empty($_cached)) {
    $out = '';
    if($host) $out .= $_cached['host'];
    if($path) $out .= $_cached['path'];
    if($file) $out .= ($host || $path ? '/' : '').$_cached['file'];
    return $out;
  }
  $s = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') ? 's' : '';
  $_host = "http$s://";
  if(isset($_SERVER['PHP_AUTH_USER'])) {
    $_host .= $_SERVER['PHP_AUTH_USER'];
    if(!empty($_SERVER['PHP_AUTH_PW']))
      $_host .= ':'.$_SERVER['PHP_AUTH_PW'];
    $_host .= '@';
  }
  if(isset($_SERVER['SERVER_NAME'])) $_host .= $_SERVER['SERVER_NAME'];
  elseif(isset($_SERVER['SERVER_ADDR'])) $_host .= $_SERVER['SERVER_ADDR'];
  else $_host .= '127.0.0.1';
  $_cached['host'] = $_host;
  $_file = $_path = '';
  $root = isset($_SERVER['DOCUMENT_ROOT'])
    ? preg_quote(strtr($_SERVER['DOCUMENT_ROOT'],'\\','/'))
    : '';
  if(isset($_SERVER['SCRIPT_FILENAME'])) {
    $_file = strtr($_SERVER['SCRIPT_FILENAME'],'\\','/');
    $dir = strtr(dirname($_file), '\\', '/');
  }
  $_path = $_cached['path'] = '/'.trim(preg_replace("/^$root/",'',$dir),'\\/');
  $_file = $_cached['file'] = basename($_file);
  $func = __FUNCTION__;
  return $func($host,$path,$file);
}

// http://coding-talk.com/f14/hmmm-2995/index3.html
function request_ip($trust_proxy = false) {
  if($trust_proxy) {
    $proxies = array(
      'HTTP_CLIENT_IP'        , 'HTTP_X_FORWARDED_FOR'
    , 'HTTP_X_FORWARDED'      , 'HTTP_X_CLUSTER_CLIENT_IP'
    , 'HTTP_FORWARDED_FOR'    , 'HTTP_FORWARDED'
    , 'HTTP_PC_REMOTE_ADDR'   , 'HTTP_X_COMING_FROM'
    , 'HTTP_FROM'             , 'HTTP_COMING_FROM'
    , 'HTTP_X_REAL_IP'        , 'HTTP_X_FWD_IP_ADDR'
    , 'HTTP_X_WAP_CLIENT_IP'  , 'HTTP_X_H3G_CLIENT_IP'
    , 'HTTP_X_DRUTT_CLIENT_IP', 'HTTP_X_WAP_PERSONALIZATION'
    , 'HTTP_X_NOKIA_IPADDRESS', 'HTTP_YAHOOREMOTEIP'
    , 'HTTP_CAF_PROXIED_HOST' , 'HTTP_X_WAP_NETWORK_CLIENT_IP'
    , 'HTTP_USER_IP'          , 'HTTP_X_FROM'
    , 'HTTP_X_FH_IP'          , 'HTTP_X_WAPIPADDR'
    , 'HTTP_REMOTE_ADDR'      , 'HTTP_USERIP'
    , 'HTTP_X_NX_CLIP'        , 'HTTP_X_INTEROP_IP_ADDRESS'
    , 'HTTP_X_WAP_PROXY_IP'   , 'HTTP_CLIENT'
    , 'HTTP_FORWARDED_FOR_IP' , 'HTTP_X_FORWARDED_FOR_IP'
    , 'HTTP_X_REMOTE_ADDR'    , 'HTTP_HTTP_X_FORWARDED_FOR'
    , 'HTTP_X_CLIENT'         , 'HTTP_X_GTM_FORWARD_SERVER_IP'
    , 'HTTP_X_JINNY_IP'       , 'HTTP_OAS_IP'
    , 'HTTP_REQUEST_IP'       , 'HTTP_FRAMED_IP_ADDRESS'
    , 'HTTP_X_XORWARDED_FOR'  , 'HTTP_X_UP_FORWARDED_FOR'
    , 'HTTP_X_UP_SGSN_IP'     , 'HTTP_IGSOURCEADDRESS'
    , 'HTTP_X_TINYPROXY'      , 'HTTP_X_UCOPIA_FORWARDED_FOR'
    , 'HTTP_WACLIENTIP'       , 'HTTP_X_CISCO_BBSM_CLIENTIP'
    , 'HTTP_HTTP_VIA'         , 'HTTP_VIA'
    , 'HTTP_IPSESSIONBEGIN'   , 'HTTP_Y_RA'
    );
    foreach($proxies as $p)
      if(!empty($_SERVER[$p])) {
        sscanf($_SERVER[$p], '%[^,]', $ip);
        if(is_remote_addr($ip)) return $ip;
      }
  }
  sscanf($_SERVER['REMOTE_ADDR'], '%[^,]', $ip);
  return $ip;
}
function ip($tp = false) { return request_ip($tp); } // alias

/**
 * Checks if an IP is an IP address and is not in the ranges
 * reserved for intranet use e.g. 192.168.x.x, 127.x.x.x, 10.10.x.x...
 */
function is_remote_addr($ip) {
  return false !== filter_var($ip, \FILTER_VALIDATE_IP
  , \FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE);
}

function is_ip($ip) {
  return false !== filter_var($ip, \FILTER_VALIDATE_IP);
}
function is_https() {
  return !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off';
}
function request_is_xhr() {
  return strtolower(v($_SERVER['HTTP_X_REQUESTED_WITH'])) == 'xmlhttprequest';
}
function server_protocol() {
  return v($_SERVER['SERVER_PROTOCOL'], 'HTTP/1.0');
}
function user_agent() {
  return v($_SERVER['HTTP_USER_AGENT'], '');
}
function request_length() {
  return (int)v($_SERVER['CONTENT_LENGTH'], 0);
}
function request_base() {
  return current_url(0,1,0);
}
function request_file() {
  return current_url(0,0);
}
function request_path() {
  return current_url(0);
}

function referer($force_same_host = false, $allow_override = true) {
  if($allow_override && isset($_REQUEST['_referer']))
    $ref = $_REQUEST['_referer'];
  else $ref = v($_SERVER['HTTP_REFERER']);
  if($force_same_host) {
    // Check if host matches server_name, or if no server_name, server_addr
    $_host = v($_SERVER['SERVER_NAME'], v($_SERVER['SERVER_ADDR']));
    if(parse_url($ref, \PHP_URL_HOST) == $_host) return $ref;
  } else return $ref;
}

// #############################################################################
// RESPONSE HANDLING FUNCTIONS #################################################
// #############################################################################

// route('GET|POST /(?<bar>.*)/?', function($e){ echo $e['bar']; });
// @todo document
function route($rule, callable $fn, $uri = null) {
  $uri = $uri ?: (getenv('PATH_INFO') ?: '/');
  list($methods, $re) = explode(' ', $rule, 2);
  list($methods, $req) = array(explode('|',$methods), _method());
  $method_matches = (in_array($req, $methods) || $methods[0] == 'ANY');
  $path_matches   = preg_match('#^/'.trim($re, '/').'$#', $uri, $args) > 0;
  if($method_matches && $path_matches) return $fn($args);
}

// Reverse route
function url_for($route = '', $omit_filename = false) {
  $root = preg_quote(strtr(v($_SERVER['DOCUMENT_ROOT']),'\\','/'));
  $self  = strtr(v($_SERVER['SCRIPT_FILENAME']),'\\','/');
  if($omit_filename) $self = dirname($self);
  return '/'.trim(preg_replace("/^$root/", '', $self), '\\/').$route;
}

function encrypted_cookie_session_start() {
  // ini_set('session.save_handler', 'sqlite');
  // ini_set('session.auto_start', 1);
  // ini_set('session.save_path', '0;%APPDATA%/Roaming/PHPSESSION/');
  ini_set('session.use_cookies', 1);
  ini_set('session.use_only_cookies', 1);
  ini_set('session.referer_check', server_name());
  ini_set('session.use_trans_sid', 0);
  ini_set('session.hash_function', 'whirlpool');
  ini_set('session.hash_bits_per_character', 5);
  ini_set('session.cookie_lifetime', 2851200); // 33 Days
  if(session_status() != \PHP_SESSION_ACTIVE) {
    session_name(c('kafene.sid'));
    $void = function(){ return true; };
    $get = function($k){ return cookie($k); };
    $set = function($k,$v){ cookie($k,$v); };
    session_set_save_handler($void, $void, $get, $set, $void, $void);
    session_set_cookie_params(2097152, '/', server_name(), false, true);
    # session_cache_limiter('private_no_expire');
    session_cache_expire(2097152);
    if(function_exists('session_register_shutdown'))
      session_register_shutdown();
    else register_shutdown_function('session_write_close');
    session_start();
  }
}

// not really much of an object, just a holder for some variables.
class response {
  static
    $status = 200
  , $body = null
  , $type = 'text/html; charset=utf-8'
  , $cookies = array()
  , $session = array()
  , $headers = array();
}

// Send json
function send_json($json, $options = 0, $cb = 'callback') {
  $json = json_encode($json, $options);
  $func = null;
  if(array_key_exists('HTTP_JSONP_CALLBACK', $_SERVER)
  &&  strlen($_SERVER['HTTP_JSONP_CALLBACK']) > 0)
    $func  = $_SERVER['HTTP_JSONP_CALLBACK'];
  elseif(array_key_exists($cb, $_REQUEST) && strlen($_REQUEST[$cb]) > 0)
    $func = $_REQUEST[$cb];
  if($func) $json = sprintf("%s(%s);\n", $func, $json);
  response::$status = 200;
  response::$headers['Content-Type'] = 'application/json';
  response::cache(false);
  response::write($json);
  response::send();
}

// Send redirect response
function redirect($url, $code = 303) {
  response::$status = $code;
  response::$headers['Location'] = $url;
  response::send(false);
}

// Set cache expire time (default 95 days) or false for no cache
// @todo - is this a good name for the function?
// @todo - maybe use session_cache_limiter
function response_cache($expire = '+95 Days') {
  if($expire === false) {
    $modified = strtotime('-33 Days');
    response::$headers['Expires'] = gmdate('D, d M Y H:i:s \G\M\T', $modified);
    response::$headers['Last-Modified'] = date('D, d M Y H:i:s \G\M\T', $modified);
    response::$headers['Cache-Control'][] = 'no-store, no-cache, must-revalidate, max-age=0';
    response::$headers['Cache-Control'][] = 'post-check=0, pre-check=0';
    response::$headers['Pragma'] = 'no-cache';
  } else {
    $expire = is_int($expire) ? $expire : (strtotime($expire) ?: $expire);
    response::$headers['Expires'] = gmdate('D, d M Y H:i:s \G\M\T', $expire);
    response::$headers['Cache-Control'] = 'max-age='.($expire - time());
  }
}

function response_set_header($k, $v) {
  if($v === false) unset(response::$headers[$k]);
  else response::$headers[$k] = $v;
}

function response_set_session($k, $v) {
  if($v === false) unset(response::$session[$k]);
  else response::$session[$k] = $v;
}

function response_set_cookie($k, $v) {
  if($v === false) unset(response::$cookies[$k]);
  else response::$cookies[$k] = $v;
}

function response_set_type($mime) {
  if($mime === false) unset(response::$type);
  else response::$type = get_mime_from_string($mime);
}

// text/plain, text/css, text/html, image/vnd.microsoft.icon
// Note - binary types where a charset makes no sense - append with `;`
function get_mime_from_string($mime, $default = 'text/html') {
  $m = $mime;
  switch($m) {
    case 'js':    $m = 'application/javascript'; break;
    case 'jsonp': $m = 'application/javascript'; break;
    case 'xjs':   $m = 'application/x-javascript'; break;
    case 'json':  $m = 'application/json'; break;
    case 'rss':   $m = 'application/rss+xml'; break;
    case 'xml':   $m = 'text/xml'; break; // or application/xml
    case 'xhtml': $m = 'application/xhtml+xml'; break;
    case 'md':    $m = 'text/x-markdown'; break;
    default:      $m = $default; break;
  }
  if(stripos($m, ';') === false)
    $m .= '; charset='.(strtolower(ini_get('default_charset') ?: 'utf-8'));
  else $m = trim($m, ';');
  return $m;
}

function response_write($str) {
  if($str === false) response::$body = null;
  else response::$body .= $str;
}

function response_set_status($code) {
  if($code === false) unset(response::$status);
  elseif(is_int($code)) response::$status = $code;
}

function response_reset() {
  response::$status = 200;
  response::$type = 'text/html; charset=utf-8';
  response::$body = null;
  response::$cookies = array();
  response::$session = array();
  response::$headers = array();
}

function response_send_status() {
  $code = is_int(response::$status)
        ? response::$status : 200;
  if(function_exists('http_response_code')) {
    http_response_code($code);
  } else {
    header('Status: '.$code, true, $code);
  }
}

function response_send_type() {
  $type = response::$type;
  if(stripos($type, 'charset') === false)
    $type .= '; charset=utf-8';
  if(!array_key_exists('Content-Type', response::$headers))
    header('Content-Type: '.response::$type);
}

function response_send_session() {
  if(session_status() != \PHP_SESSION_ACTIVE
  && session_status() != \PHP_SESSION_DISABLED)
    session_start(c('kafene.sid'));
  foreach(response::$session as $k => $v)
    if($v === false) unset($_SESSION[$k]);
    else $_SESSION[$k] = $v;
}

function response_send_cookies() {
  foreach(response::$cookies as $k => $v) {
    if($v === false) $expire = time() - 2592000;
    else $expire = time() + c('kafene.cookie_expire');
    if($v) $v = encrypt(json_encode(array(time(), $v)), get_encryption_key());
    setcookie($k, $v, $expire, '/', server_name(null), false, true);
  }
}

function response_send_headers() {
  foreach(response::$headers as $k => $v) {
    if(is_array($v)) {
      foreach($v as $q)
        // false = don't clobber eachother
        header($k.': '.$q, false);
    } else {
      header($k.': '.$v);
    }
  }
}

function response_send($with_body = true) {
  // If using response::$body to send content, use that
  // otherwise use contents of output buffer
  $body = response::$body ?: ob_get_clean();
  if(!headers_sent()) {
    response_send_status();
    response_send_type();
    response_send_headers();
    response_send_cookies();
    response_send_session();
  }
  if($with_body == false) exit;
  exit($body);
}

function cookie($k, $v=null) {
  if(!is_string($k)) return;
  $key = get_encryption_key();
  $exp = c('kafene.cookie_expire');
  if($v !== null) response_set_cookie($k, $v);
  else return ((isset($_COOKIE[$k]))
    && (($v = json_decode(decrypt($_COOKIE[$k]), true))
    && ($v[0] < (time() + $exp)))) ? $v[1] : false;
}

// Cookie thingy.
// cookie('name', 'value'); -> set stored cookie
// cookie('name', false); -> unset client cookie
// cookie('name'); -> get client cookie
// cookie(COOKIE_FLAG_COOKIE_SEND); -> send stored cookies
// cookie(); -> get all stored cookies
/*
function cookie($k = null, $v = null) {
  static $_cookies = array();
  $key = get_encryption_key();
  $exp = c('kafene.cookie_expire');
  if($k === null && $v === null) return $_cookies; // get all
  if(!is_string($k)) return;
  if($k === 'COOKIE_FLAG_COOKIE_SEND') { // send
    foreach($_cookies as $kkk => $vvv) {
      if($vvv === false) $expires = time() - 2592000; // -30 days
      else $expires = time() + $exp;
      if($v) $v = encrypt(json_encode(array(time(), $v)), $key);
      setcookie($kkk, $vvv, $expires, '/', server_name(null), false, true);
    }
  }
  if($v !== null) $_cookies[$k] = $v; // set
  return ((isset($_COOKIE[$k])) // get
    && (($v = json_decode(decrypt($_COOKIE[$k]), true))
    && ($v[0] < (time() + $exp)))) ? $v[1] : false;
}
function send_cookies() {
  cookie('COOKIE_FLAG_COOKIE_SEND');
}
*/

// #############################################################################
// ARRAY FUNCTIONS #############################################################
// #############################################################################

function array_first(array $a) { return reset($a); }
function array_last(array $a) { return end($a); }
function array_key_first(array $a) { reset($a); return key($a); }
function array_key_last(array $a) { end($a); return key($a); }

/**
 * recursive array_map
 * Example: map([], function(&$key, &$value) {});
 * @param array $a
 * @param callable $f
 */
function array_map_recursive(array &$a, callable $f) {
  $o = array();
  foreach($a as $k => $v)
    if(is_array($v)) map($v,$f);
    else $o[$k] = $f($k,$v);
  return $o;
}
function map(&$a, callable $f) { return map($a, $f); } // alias

// Flatten an array. Keys are kind of kept, but to avoid collisions,
// They are appended with "//id" where id is a unique id
function array_flatten(array $a) {
  $o = array();
  foreach($a as $k=>$v)
    is_array($v)
    ? $o = array_merge($o, array_flatten($v))
    : $o[$k.'//'.uniqid($k,1)] = $v;
  return $o;
}
function flatten($a) { return array_flatten($a); } // alias

/**
 * Sort a 2-d array by a certain column
 * $people = [
 *   ['name' => 'bob', 'age' => 23]
 * , ['name' => 'sam', 'age' => 18]
 * , ['name' => 'ken', 'age' => 30]
 * , ['name' => 'amy', 'age' => 44]
 * ];
 * var_dump($people); // > bob, sam, ken, amy
 * var_dump(array_index_sort($people, 'name')); // > sam, ken, bob, amy
 * var_dump(array_index_sort($people, 'age')); // > amy, ken, bob, sam
 * @param array $a - 2-dimensional array
 * @param string $col - column to sort on
 * @param int $dir - PHP SORT_ constant, see manual for array_multisort()
 * @param int $mode - PHP SORT_ constant, see manual for array_multisort()
 * @return array
 */
function array_index_sort(array $a, $col, $dir = \SORT_DESC, $mode = \SORT_REGULAR) {
  $temp = array();
  foreach($a as $key => $val)
    if(isset($val[$col]))
      $temp[$key] = $val[$col];
    else $temp[] = $val;
  array_multisort($temp, $dir, $mode, $a);
  return $a;
}

function array_to_rss(array $items, $url = '//localhost/', $title = 'Blog'
, $link_id = 'id', $time_id = 'time', $title_id = 'title', $body_id = 'body'
, $link_fmt = 'http://localhost/site.php?id={{id}}&from=rss') {
  $o = '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
     . "<title>$title</title><description>$title - RSS Feed</description>";
  foreach($items as $i) {
    $link = str_ireplace('{{id}}', $i[$link_id], $link_fmt);
    $o .= "<item><title>{$item[$title_id]}</title><link>$link</link>"
    . '<pubDate>'.date(\DATE_RSS, is_int($i[$time_id]) ? $i[$time_id]
    : (strtotime($i[$time_id]) ?: $i[$time_id])).'</pubDate>'
    . '<guid isPermaLink="false">'.$link.'</guid>'.(isset($i[$body_id])
    ? "<description><![CDATA[\n".str_replace(']', '&#93;', $i[$body_id])
    . "\n<p><b>".'<a href="'.$link.'">#</a></b></p>\n]]></description>'
    : '').'</item>';
  } return $out.'</channel></rss>';
}

// #############################################################################
// STRING THINGS ###############################################################
// #############################################################################

function strip_control_chars($s) { return preg_replace('/\p{C}+/u','',$s); }
// Return a string with only numeric characters remaining:
function n($n) { return intval(preg_replace('/[^0-9]/', '', $n)); }

function random_str($length, $include_symbols = true) {
  $out = '';
  $pool = $include_symbols ? range('!','~')
        : array_merge(range('A','Z'), range('a','z'), range('0','9'));
  $pool_size = count($pool) - 1;
  for($i = 0; $i < $length; $i++)
    $out .= $pool[mt_rand(0, $pool_size)];
  return $out;
}

/**
 * Replace characters that equate to & with &amp; in URLs
 * @param string $url - url to replace in
 * @param string $to - what to replace with, generally either &amp; or %26
 */
function urlamp($url, $to = '&amp;') {
  $url = str_replace(array('&amp;', '%26', '&#38;', '&#x26;'), '&', $url);
  return str_replace('&', $to, $url);
}

/**
 * Size formatter. Goes up to yobibytes so it should be good for a while.
 * @url <http://stackoverflow.com/questions/2510434>
 * @param int $size - size to format
 * @param string $format - format for sprintf
 * @return string
 */
function size_format($size, $format = '%-7.2f %s') {
  $ext = array('B','K','M','G','T','P','E','Z','Y');
  $bytes = max($size, 0) ?: 0;
  $pow = (int)min(floor(log($bytes) / log(1024)), count($ext) - 1);
  $bytes = round($bytes /= pow(1024, $pow), 2);
  return sprintf($format, $bytes, $ext[$pow].($pow > 0 ? 'iB' : ''));
}

/**
 * Makes a slug into an ASCII-only URL slug thing
 * echo slug('šāģāa éèêëiîïoöôôuùûüaâäÅ'); // > sagaa-eeeeiiioooouuuuaaaa
 * @param string $str - string to remove accents from
 * @param int $max - max length of slugged string
 * @param string $slug - slug character to use
 * @return string
 */
function slug($str, $max = 64, $slug = '-') {
  if(false !== @iconv('UTF-8', 'ASCII//TRANSLIT', $str))
    $str = str_replace(array("'",'`','^','"',':',','), ''
    , iconv('UTF-8', 'ASCII//TRANSLIT', $str));
  $acc = 'acute|caron|cedil|circ|grave|lig|orn|ring|slash|tilde|uml|th';
  $str = html_entity_decode(preg_replace('#&([a-z]{1,2})(?:'.$acc.');#ix'
  , '$1', htmlentities($str, \ENT_QUOTES, 'UTF-8')), \ENT_QUOTES, 'UTF-8');
  // $str = preg_replace('/[^\pL\pNd]+/u', $slug, strtolower($str));
  $str = preg_replace('/[^a-z0-9]+/', $slug, strtolower($str));
  $str = preg_replace('/'.preg_quote($slug).'+/', $slug, $str);
  $str = trim($str, $slug);
  $ret = substr($str, 0, $max);
  if(false !== ($lat = strrpos($ret, $slug)) && $str != $ret)
    $ret = substr($ret, 0, $lat);
  return trim($ret, $slug);
}

// Remove non safe characters, extra whitespace, duplicate symbols
function ss($str) {
  $rep = array('/[^\w\-\. ]+/u', '/\s\s+/', '/\.\.+/',  '/--+/', '/__+/');
  $str = preg_replace($rep, array(' ', ' ', '.', '-', '_'), $str);
  return trim($str, '-._ ');
}

function str_to_alnum($str, $extra = ' ') {
  return preg_replace('/[^A-Za-z0-9'.preg_quote($extra).']/', '', $str);
}

/**
 * e.g. -5 -> America/New_York
 * @param int $offset
 * @param bool $dst
 * @return string
 */
function utc_offset_to_timezone($offset, $dst = false) {
  return timezone_name_from_abbr('', (int)$offset * 3600, $dst);
}

/**
 * Truncates a string to some length without cutting in the middle of a word.
 * @param string $str - the string to truncate
 * @param int $len - length to truncate to
 * @param string $append - string to append at end
 * @param string $ws - word separator character
 */
function truncate($str, $len, $append = '...', $ws = ' ') {
  $ret = substr($str, 0, $len);
  if(false !== ($rws = strrpos($ret, $ws)) && $str != $ret)
    $ret = substr($ret, 0, $rws);
  return $ret.($ret != $str ? $append : '');
}

function minify($str, array $extra_removals = array()) {
  $rmv = array_merge(array("\r"=>'',"\n"=>' ',"\t"=>' '), $extra_removals);
  $str = str_replace(array_keys($rmv), array_values($rmv), $str);
  return trim(preg_replace('/\s+/',' ', $str));
}

/**
 * Converts links to clickable links
 * @package linkify
 * @version 20101010_1000
 * @copyright Jeff Roberson 2010
 * @author Jeff Robertson <http://jmrware.com>
 * @license MIT <http://www.opensource.org/licenses/mit-license.php>
 * @link <https://github.com/jmrware/LinkifyURL>
 * @param string $text
 * @return string
 */
function linkify($text) {
  $re = '/(\()((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\))
  |(\[)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\])
  |(\{)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\})
  |(<|&(?:lt|\#60|\#x3c);)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)
   (>|&(?:gt|\#62|\#x3e);)|((?: ^| [^=\s\'"\]]) \s*[\'"]?| [^=\s]\s+)
   ( \b(?:ht|f)tps?:\/\/[a-z0-9\-._~!$\'()*+,;=:\/?#[\]@%]+
   (?:(?!&(?:gt|\#0*62|\#x0*3e);| &(?:amp|apos|quot|\#0*3[49]|\#x0*2[27]);
   [.!&\',:?;]?(?:[^a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]|$)) &
   [a-z0-9\-._~!$\'()*+,;=:\/?#[\]@%]*)*[a-z0-9\-_~$()*+=\/#[\]@%])/imx';
  $replace = '$1$4$7$10$13<a href="$2$5$8$11$14">$2$5$8$11$14</a>$3$6$9$12';
  return preg_replace($re, $replace, $text);
}
function linkify_html($text) {
  $text = preg_replace('/&apos;/', '&#39;', $text);
  $pat = '%([^<]+(?:(?!<a\b)<[^<]*)*|(?:(?!<a\b)<[^<]*)+)
  |(<a\b[^>]*>[^<]*(?:(?!</a\b)<[^<]*)*</a\s*>)%ix';
  return preg_replace_callback($pat, function($m){
    return isset($m[2]) ? $m[2] : linkify($m[1]);
  }, $text);
}

/**
 * $html_template = '<html><?= $html ?></html>';
 * $body_template = '<body><?= $body ?></body>';
 * $body_vars = ['body' => 'hello, world.'];
 * $body = render($body_template, $body_vars, 0);
 * $html_vars = ['html' => $body];
 * echo render($html_template, $html_vars, 0);
 * @param string $_view - content to render
 * @param array $_vars - variables to use in the rendered view
 * @param bool|callable $sanitize - whether to sanitize each variable
 *   or if it is callable, the callable func will be used to sanitize.
# */
function render($_view, array $_vars = array(), $sanitize = true) {
  if($sanitize !== false)
    foreach($_vars as &$v)
      $v = is_callable($sanitize) ? $sanitize($v) : h($v);
  ob_start();
  extract($_vars, \EXTR_SKIP);
  !is_readable($_view)
    ? eval("?>$_view")
    : include($_view);
  return ob_get_clean();
}

/**
 * MicroTpl
    $vars['title'] = 'MicroTpl';
    $vars['messages'][]['txt'] = 'Hello';
    $vars['messages'][]['txt'] = 'World';
    $vars['footer'] = '<footer><b>Some footer...</b></footer>';
    $doc = '<!DOCTYPE html><html><head>
    <title>{{title}}</title></head><body>
    <header><h1>{{title}}</h1></header>
    {{@messages}}<p>{{txt}}</p>{{/messages}}
    {{test="Footer:"}}{{test}}
    {{&footer}}</body></html>';
    echo MicroTpl($doc, $vars);
 * @link <http://github.com/unu/microtpl>
 * @param string $_tpl - template to render
 * @param array $_vars - variables to use in template
 * @param bool $_echo - true = return rendered string, false = print it.
 */
function MicroTpl($_tpl, array $_vars = array(), $_ret = true) {
  $_flg = '\ENT_QUOTES|\ENT_HTML5|\ENT_DISALLOWED|\ENT_SUBSTITUTE';
  $_parsed = preg_replace(array(
    '_{{\@([^}]+)}}_' # {@list} list array
  , '_{{\?([^}]+)}}_' # {?bool} show block on true
  , '_{{\!([^}]+)}}_' # {!bool} show block on false
  , '_{{\/([^}]+)}}_' # {/list} end of array or block
  , '_{{\&([^}]+)}}_' # {&var} echo unescaped var
  , '_{{([a-zA-Z0-9]+)}}_' # {var} echo escaped var
  , '_{{([a-zA-Z0-9]+=.+)}}_' # {var='value'} assign value to var
  , '_{{-?([^ }][^}]*)}}_' # {php code} process php code
  ), array(
    '<?php $_sv_\1 = get_defined_vars();'
    . 'foreach((isset($\1) && is_array($\1) ? $\1 : array()) as $_item) { '
    . 'if(is_array($_item)) extract($_item); ?>'
  , '<?php if(isset($\1) && !!$\1) { ?>'
  , '<?php if(!isset($\1) || !$\1) { ?>'
  , '<?php } if(isset($_sv_\1) && is_array($_sv_\1)) extract($_sv_\1); ?>'
  , '<?= isset($\1) ? $\1 : "" ?>'
  , '<?= isset($\1) ? htmlentities(\$\1, '.$_flg.') : "" ?>'
  , '<?php $\1; ?>'
  , '<?php \1 ?>'
  ), $_tpl);
  if($_ret) ob_start();
  extract((array)$_vars, \EXTR_SKIP);
  eval("?>$_parsed");
  if($_ret) return ob_get_clean();
}

// #############################################################################
// CRYPTO FUNCTIONS ############################################################
// #############################################################################

function encrypt($str, $key = null, $algo = 'rijndael-256', $mode = 'cbc') {
  $key = $key ?: get_encryption_key();
  $key = mb_substr($key, 0, mcrypt_get_key_size($algo, $mode));
  $iv_size = mcrypt_get_iv_size($algo, $mode);
  $iv = mcrypt_create_iv($iv_size, \MCRYPT_DEV_URANDOM);
  $encrypted = base64_encode(mcrypt_encrypt($algo, $key, $str, $mode, $iv));
  return sprintf('%s|%s', $encrypted, base64_encode($iv));
}

function decrypt($str, $key = null, $algo = 'rijndael-256', $mode = 'cbc')  {
  $key = $key ?: get_encryption_key();
  $key = mb_substr($key, 0, mcrypt_get_key_size($algo, $mode));
  list($str, $iv) = explode('|', $str);
  $str = base64_decode($str);
  $iv = base64_decode($iv);
  return rtrim(mcrypt_decrypt($algo, $key, $str, $mode, $iv), "\x0");
}

function get_encryption_key() {
  if(defined('ENCRYPTION_KEY')) return ENCRYPTION_KEY;
  if(function_exists('c') && c('kafene.key')) return c('kafene.key');
  $eot = \PHP_EOL.'<br>'.\DIRECTORY_SEPARATOR;
  $_unique  = php_uname('a').$eot;
  $_unique .= 'uid '.getmyuid().$eot;
  $_unique .= 'sapi '.php_sapi_name().$eot;
  $_unique .= 'include path '.get_include_path().$eot;
  $_unique .= 'zend engine '.zend_version().$eot;
  $_unique .= 'php version '.phpversion().$eot;
  $_unique .= 'extensions '.implode(',', get_loaded_extensions()).$eot;
  return hash(longest_available_hash_algo(), $_unique);
}

function rebase($n, $from = 10, $to = 62) {
  return ($from > 32 || $to > 32)
    ? gmp_strval(gmp_init($n, $from), $to)
    : base_convert($n, $from, $to);
}

function longest_available_hash_algo() {
  foreach(hash_algos() as $algo)
    $avail[strlen(hash($algo,''))] = $algo;
  ksort($avail);
  return array_pop($avail);
}

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

// #############################################################################
// FILE FUNCTIONS ##############################################################
// #############################################################################

/**
 * Get the mime type for a file with finfo
 * 1. Checks if finfo_open is available and file is readable
 * 2. Sets mime to finfo-detected mime and confirms not empty
 * 3. Strips `; charset=...` or any extra semicolon-delimited data after
 *    and check that stripped mime is not empty
 * @param string $file - an actual local file
 * @param string $def - default mime type to return on failure
 * @return string
 */
function file_mime_type($file, $def = 'application/octet-stream') {
  return ((function_exists('finfo_open') && is_readable($file))
  && ($mime = finfo_file(finfo_open(\FILEINFO_MIME), $file))
  && (sscanf($mime, '%[^;]', $_mime) && $_mime))
    ? $_mime : $def;
}
function mime($file, $def = 'application/octet-stream') { // alias
  return file_mime_type($file, $def);
}

/**
 * Glob, but recursive.
 * @param string $pat - pattern to glob
 * @param int $flags - combination of glob falgs. Doesn't work with \GLOB_BRACE.
 * @link <http://php.net/manual/en/function.glob.php#106595>
 */
function glob_recursive($pat, $flags = 0) {
  $files = glob($pat, $flags);
  foreach(glob(dirname($pat).'/*', \GLOB_ONLYDIR|\GLOB_NOSORT) as $dir)
    $files = array_merge($files, glob_recursive($dir.'/'.basename($pat), $flags));
  return $files;
}

# Like a recursive glob(). can match for a file regex pattern.
function read_dir_recursive($dir = '.', $re = '/^.*$/i') {
  $dir = realpath($dir);
  foreach(new \RegexIterator(
    new \RecursiveIteratorIterator(
      new \RecursiveDirectoryIterator($dir
      ,   \FilesystemIterator::KEY_AS_PATHNAME
        | \FilesystemIterator::CURRENT_AS_FILEINFO
        | \FilesystemIterator::SKIP_DOTS
      ), \RecursiveIteratorIterator::SELF_FIRST
    ), $re, \RecursiveRegexIterator::GET_MATCH
  ) as $v) $out[] = $v[0];
  return $out;
}

// from limonade framework <https://raw.github.com/sofadesign/limonade>
function readfile_chunked($file, $retbytes = true, $chunksize = 1048576) {
  if(($fh = fopen($file, 'rb')) === false) return false;
  $buf = ''; $ct  = 0; ob_start();
  while(!feof($fh)) {
    $buf = fread($fh, $chunksize);
    echo $buf; ob_flush(); flush();
    if($retbytes) $ct += strlen($buf);
    set_time_limit(0);
  }
  ob_end_flush(); $fc = fclose($fh);
  return $retbytes && $fc ? $ct : $fc;
}

function send_file_chunked($file, $retbytes = true, $chunksize = 1048576) {
  header('Content-Disposition: attachment; filename='.basename($file));
  header('Content-Encoding', 'chunked');
  header('Transfer-Encoding', 'chunked');
  header('Content-Type: '.file_mime_type($file));
  header('Content-Length: '.filesize($file));
  header('Connection', 'keep-alive');
  exit(readfile_chunked($file, false, 4096));
}

function file_permissions($p) {
  if(!is_file($p) && !is_int($p) && !ctype_digit($p)) return false;
  return substr(sprintf('%o', is_file($p) ? fileperms($p) : $p), -4);
}

function file_extension($filename) {
  if(false !== ($pos = strrpos($filename, '.')));
    return substr($filename, $pos + 1);
}

// Send file download
function send_file_download($file, $chunk = 1048576) {
  if(false === ($fh = @fopen($file,'rb'))) exit('read error');
  if(!headers_sent()) {
    if(ini_get('zlib.output_compression'))
       ini_set('zlib.output_compression', 0);
    header('Content-Description: File Transfer', true);
    header('Cache-Control: must-revalidate,private,post-check=0,pre-check=0');
    header('Content-Disposition: attachment; filename='.basename($file));
    header('Content-Transfer-Encoding: binary');
    header('Content-Length: '.filesize($file));
    header('Content-Type: application/force-download');
    header('Content-Transfer-Encoding: binary');
  }
  while(!feof($fh)) {
    echo fread($fh, $chunk);
    ob_flush(); flush();
    set_time_limit(0);
  }
  ob_end_flush(); fclose($fh); exit;
}


// #############################################################################
// PDO/DATABASE ################################################################
// #############################################################################

/**
 * Provides a database wrapper around the PDO service to help reduce the effort
 * to interact with a RDBMS such as SQLite, MySQL, or PostgreSQL.
 * @link <https://github.com/xeoncross/kit>
 */
class db {
  public $db, $driver, $pk;
  static $queries = array();
  public function __construct(\PDO $pdo, $pk = 'id') {
    $this->db = $pdo;
    $this->pk = $pk;
    $this->db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    return $this->pdo;
  }
  function quote($value) {
    return $this->db->quote($value);
  }
  // Fetch a column offset from the result set (COUNT() queries)
  function column($query, $params = null, $key = 0) {
    if($st = $this->query($query, $params))
      return $st->fetchColumn($key);
  }
  // Fetch a single query result row
  function row($query, $params = null) {
    if($st = $this->query($query, $params))
      return $st->fetch();
  }
  // Fetches an associative array of all rows as key-value pairs (first
  // column is the key, second column is the value).
  function pairs($query, $params = null) {
    $data = array();
    if($st = $this->query($query, $params))
      while($row = $st->fetch(\PDO::FETCH_NUM))
        $data[$row[0]] = $row[1];
    return $data;
  }
  // Fetch all query result rows
  function fetch($query, $params = null, $col = null) {
    if(!$st = $this->query($query, $params)) return;
    // Return an array of records
    if($col === null) return $st->fetchAll();
    // Fetch a certain column from all rows
    return $st->fetchAll(\PDO::FETCH_COLUMN, $col);
  }
  function query($query, $params = NULL) {
    $st = $this->db->prepare(static::$queries[] = $query);
    $st->execute((array)$params);
    return $st;
  }
  function insert($tbl, array $data, array $keys_allowed = array()) {
    if(!empty($keys_allowed)) $data = array_intersect_key($data,$keys_allowed);
    if(empty($data)) return;
    $q = "REPLACE INTO `$tbl` (`".implode('`,`', array_keys($data)).'`) VALUES '
    . '('.rtrim(str_repeat('?,', count($data = array_values($data))), ', ').')';
    return $this->query($q, $data)
      ? ($this->pdo->inTransaction() ? true : $this->pdo->lastInsertId())
      : false;
  }
  function update($tbl, $data, $pk) {
    $keys = implode('`= ?, `', array_keys($data));
    $q = "UPDATE `$tbl` SET `$keys` = ? WHERE `".$this->pk."` = ?";
    if($st = $this->query($q, array_values($data + array($pk))))
      return $this->pdo->inTransaction() ? true : $st->rowCount();
  }
  function delete($tbl, $pk) {
    if($st = $this->query("DELETE FROM `$tbl` WHERE `".$this->pk."` = ?", $pk))
      return $this->pdo->inTransaction() ? true : $st->rowCount();
  }
}

function db_params(array $params, $t = '`') {
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


// #############################################################################
// EVENT CLASS #################################################################
// #############################################################################

/**
 * event listener/dispatcher class
 * @todo document
 */
class hook {
  protected static $hooks = array();
  static function on($ev, callable $fn) {
    if(!isset(static::$hooks[$ev]))
      static::$hooks[$ev] = array();
    static::$hooks[$ev][] = $fn;
  }
  static function once($ev, callable $fn) {
    $once = function() use(&$once, $ev, $fn){
      self::off($ev, $once);
      call_user_func_array($fn, func_get_args());
    };
    self::on($ev, $once);
  }
  static function off($ev = null, callable $fn = null) {
    if($ev === null && $fn === null) // Remove all
      self::$hooks = array();
    if($ev !== null && $fn === null) // Remove all for event
      unset(self::$hooks[$ev]);
    elseif((isset(self::$hooks[$ev])) // Remove a single hook
    && (false !== $i = array_search($fn, self::$hooks[$ev], true)))
      unset(self::$hooks[$ev][$i]);
  }
  static function hooks($ev) {
    return isset(self::$hooks[$ev]) ? self::$hooks[$ev] : array();
  }
  static function fire($ev) {
    $args = array_slice(func_get_args(), 1);
    foreach(self::hooks($ev) as $fn) {
      $res = call_user_func_array($fn, $args);
      if($res !== null) $args = $result;
    }
    return $args;
  }
}

// #############################################################################
// ARRAY ACCESS CLASS ##########################################################
// #############################################################################

// Everyone else had one and I wanted one. Arrayable object.
class a implements \ArrayAccess, \IteratorAggregate, \Countable {
  private $c, $pos;
  function __construct(array $c = array()) { $this->c = $c; $this->pos = 0; }
  function __get($k) { if(isset($this->c[$k])) return $this->c[$k]; }
  function __set($k,$v) { $this->c[$k] = $v; }
  function __isset($k) { return isset($this->c[$k]); }
  function __unset($k) { unset($this->c[$k]); }
  function offsetGet($k) { if(isset($this->c[$k])) return $this->c[$k]; }
  function offsetSet($k,$v) { is_null($k) ? $this->c[] = $v : $this->c[$k] = $v; }
  function offsetExists($k) { return isset($this->c[$k]); }
  function offsetUnset($k) { unset($this->c[$k]); }
  function count() { return count($this->c); }
  function keys() { return array_keys($this->c); }
  function getData() { return $this->c; }
  function setData(array $c) { $this->c = $c; }
  function clear() { $this->c = array(); $this->pos = 0; }
  function getIterator() { return new \ArrayIterator($this->c); }
}

// #############################################################################
// MISCELLANEOUS ###############################################################
// #############################################################################

/**
 * Hashcash is a computationally expensive operation for the sender, while being
 * easily verified by the receiver. It proves this email was worth working for
 * and isn't spam.
 * use email header: `"X-Hashcash: ".hashcash($email);`
 * @param string $email
 * @return string
 * @link <https://github.com/xeoncross/kit>
 */
function hashcash($email) {
  $ct = 0; $hc = sprintf('1:20:%u:%s::%u', date('ymd'), $email, mt_rand());
  while(strncmp('00000', sha1($hc.$ct), 5) !== 0) { ++$ct; } return $hc.$ct;
}

/* Dependency Injection? */
class i {
  static $c = array();
  static function set($id, callable $fn) { self::$c[$id] = $fn; }
  static function has($id) { return isset(self::$c[$id]); }
  static function get($id, $args = null) {
    if(!self::has($id)) return false;
    if(is_callable($fn = self::$c[$id])) self::$c[$id] = $fn($args);
    return self::$c[$id];
  }
}

/* Shorten a URL using Google's goo.gl API. Requires an API key. */
function shorten_url($url, $api_key){
  $endpoint = 'https://www.googleapis.com/urlshortener/v1';
  $ch = curl_init(sprintf('%s/url?key=%s', $endpoint, $api_key));
  curl_setopt_array($ch, array(\CURLOPT_POST => true
  , \CURLOPT_AUTOREFERER => true, \CURLOPT_FOLLOWLOCATION => true
  , \CURLOPT_UNRESTRICTED_AUTH => true, \CURLOPT_RETURNTRANSFER => true
  , \CURLOPT_HTTPHEADER => array('Content-Type: application/json')
  , \CURLOPT_POSTFIELDS => json_encode(array('longUrl' => $url))));
  $res = curl_exec($ch); curl_close($ch); return json_decode($res, true);
}

// Highlight code with pygments
function pygmentize($lang, $code) {
  $css = 'https://kafene.github.com/asset/misc/pygments.css';
  $l = urlencode($lang); $c = urlencode($code); $ch = curl_init();
  curl_setopt_array($ch, array(
    \CURLOPT_URL => 'http://pygments.appspot.com/'
  , \CURLOPT_POST => 2, \CURLOPT_RETURNTRANSFER => 1
  , \CURLOPT_POSTFIELDS => sprintf('lang=%s&code=%s', $l, $c)));
  $res = curl_exec($ch); curl_close($ch);
  return array('html' => $res, 'css' => $css);
}

// github flavored markdown via api
function github_markdown($text) {
  $ch = curl_init('https://api.github.com/markdown/raw');
  curl_setopt_array($ch, array(\CURLOPT_POST => true
  , \CURLOPT_RETURNTRANSFER => true, \CURLOPT_POSTFIELDS => $text
  , \CURLOPT_SSL_VERIFYPEER => false, \CURLOPT_UNRESTRICTED_AUTH => true
  , CURLOPT_HTTPHEADER => array('Content-Type: text/plain')));
  $ret = curl_exec($ch); curl_close($ch); return $ret;
}

# http://joshosopher.tumblr.com/post/17295179484/php-5-4-traits-closures-and-prototype-based
# A class for prototype based programming (ala javascript)
class prototype {
  private $v = array(), $f = array();
  function &__get($k) {
    if(array_key_exists($k, $this->v)) return $this->v[$k];
    elseif(array_key_exists($k, $this->f)) return $this->f[$k];
  }
  function __set($k, $v) {
    if(is_object($v) && is_callable($v)) {
      if(!array_key_exists($k, $this->f)) $this->f[$k] = array();
      if($v instanceof \Closure) $v = $v->bindTo($this);
      $this->f[$k][] = $v;
    } else $this->v[$k] = $v;
  }
  function __call($k, $a = array()) {
    if(!array_key_exists($k, $this->f)) return;
    $fs = $this->f[$k];
    if(is_array($fs)) foreach($fs as $f)
      if(null !== ($r = call_user_func_array($f, $a))) return $r;
  }
}

function days_ago($days) { return strtotime("-$days Days"); }
function days_ahead($days) { return strtotime("+ $days Days"); }
function days_in_seconds($days) { return strtotime("+$days Days", 0); }

// #############################################################################
// HTML TO ARRAY :| ############################################################
// #############################################################################

# Requires: Tidy, SimpleXML, DOM
function html_to_array($html) {
  $html = tidy_parse_string($html)->cleanRepair();
  $dom = new \DOMDocument;
  $dom->loadHTML($html);
  $xml = simplexml_import_dom($dom);
  return _html_to_array($xml);
}
function _html_to_array(\SimpleXMLElement $html) {
  $ns = $html->getDocNamespaces(true);
  $ns[null] = null;
  $cs = $attrs = array();
  $name = strtolower((string)$html->getName());
  $text = trim((string)$html);
  if(strlen($text) <= 0)
    $text = null;
  if(is_object($html)) foreach($ns as $_ns => $nsu) {
    $oattrs = $html->attributes($_ns, true);
    foreach($oattrs as $attrn => $attrv) {
      $attrn = strtolower(trim((string)$attrn));
      $attrv = trim((string)$attrv);
      $attrs[$attrn] = $attrv;
    }
    $ochildren = $html->children($_ns, true);
    foreach($ochildren as $cname => $child) {
      $cname = strtolower((string)$cname);
      $cs[$cname][] = self::_html_to_array($child);
    }
  }
  return array('name'  => $name,   'text'    => $text
             , 'attrs' => $attrs, 'children' => $cs);
}

// #############################################################################
// #############################################################################
// #############################################################################
// BELOW ARE DRAGONS ###########################################################
// #############################################################################
// #############################################################################
// DO NOT SCROLL DOWN ANY MORE #################################################
// #############################################################################
// #############################################################################
// UNDER CONSTRUCTION ##########################################################
// #############################################################################
// #############################################################################
// NOT FINISHED WORKING THESE OUT YET ##########################################
// #############################################################################
// #############################################################################
// WILL CAUSE SERVER TO EXPLODE ################################################
// #############################################################################
// #############################################################################
// TESTING AREA ################################################################
// #############################################################################
// #############################################################################
// #############################################################################

// @link <http://github.com/xeoncross/kit>
function browserID($assertion, $host = null) {
  $host = $host ?: 'http://'.getenv('HTTP_HOST');
  $c = stream_context_create(array('http' => array(
    'method' => 'POST'
  , 'header' => 'Content-type: application/x-www-form-urlencoded'
  , 'content'=> "assertion=$assertion&audience=$host",
  )));
  $data = file_get_contents('https://persona.org/verify', 0, $c);
  if($data AND ($data = json_decode($data, true))) return $data;
}

// @link <http://github.com/xeoncross/kit>
function www_authenticate(array $users, $realm = "SECURE", $exit = true) {
  if(!empty($_SERVER['PHP_AUTH_DIGEST'])) {
    $default = array('nonce','nc','cnonce','qop','username','uri','response');
    preg_match_all('/(\w+)="?([^",]+)"?/', $_SERVER['PHP_AUTH_DIGEST'], $m);
    $data = array_combine($m[1] + $default, $m[2]);
    $A1 = md5($data['username'].':'.$realm.':'.$users[$data['username']]);
    $A2 = md5(getenv('REQUEST_METHOD').':'.$data['uri']);
    $A0 = $data['nonce'].':'.$data['nc'].':'.$data['cnonce'].':'.$data['qop'];
    $valid_response = md5($A1.':'.$A0.':'.$A2);
    if($data['response'] === $valid_response) return true;
  }
  if(!$exit) return false;
  header('HTTP/1.1 401 Unauthorized');
  exit(header('WWW-Authenticate: Digest realm="'.$realm.'",qop="auth"'
  . ',nonce="'.hash('whirlpool', openssl_pseudo_random_bytes(64))
  . '",opaque="'.md5($realm).'"'));
}

// @link <http://github.com/xeoncross/kit>
class OAuth2 {
  public $client_id, $client_secret, $auth_url, $token_url;
  function __construct($config, $debug = false) {
    foreach($config as $k => $v) $this->$k = $v;
    $this->debug = $debug;
  }
  function getToken($redirect_uri, $code, $state, $scope = '') {
    $params = array(
      'client_id' => $this->client_id
    , 'redirect_uri' => $redirect_uri
    , 'scope' => $scope
    , 'state' => $state
    );
    if($code) {
      $params = http_build_query($params + array(
        'client_secret' => $this->client_secret
      , 'grant_type' => 'authorization_code'
      , 'code' => $code
      ));
      $c = stream_context_create(array('http' => array(
        'method'  => 'POST'
      , 'header'  => 'Content-type: application/x-www-form-urlencoded\r\n'
                   . 'Content-Length: '.strlen($params)
      , 'content' => $params
      , 'ignore_errors' => $this->debug == TRUE
      )));
      if($res = file_get_contents($this->token_url.'?'.$params, 0, $c)) {
        if($this->debug)
          return join("\n", $http_response_header)."\n\n".$res;
        if($json = json_decode($result)) return $json;
        parse_str($res, $pieces);
        return $pieces;
      }
    } else {
      $params['response_type'] = 'code';
      $redir = $this->auth_url.'?'.http_build_query($params);
      exit(header('Location: '.$redir, true, 307));
    }
  }
}

// dont even ask what this is.
/* #(C) kafene.org 2012 /Post@($Y='p/')*.md,line1=title,2=date,3='',4+=txt/md
function mi($Y){$A=$_SERVER;$C=$A['HTTP_HOST'];$B='//'.$C.$A['SCRIPT_NAME'];$D=
$Y.(@$_GET['f']?:0);$G=[];$H=0;foreach(glob("$Y*.md")?:[]as$I){$J=file($I);$K=
strtotime($J[1]);$G[$K.$H++]=[$J[0],$K,basename($I)];}@krsort($G);if(!is_file(
$D))foreach($G as$Z)@$E.="\n- [{$Z[0]}]($B?f={$Z[2]})  \n".date('Y-m-d',$Z[1]);
die("<xmp theme=cerulean><div style='width:60%;margin:0 auto'><h1><a href=$B>$C
</a></h1>\n".(@$E?:'# '.@file_get_contents($D))."</xmp><title>$C</title><script
src=//strapdownjs.com/v/0.1/strapdown.js></script>");}#mi('p/'); */

// #############################################################################
// BOTTOM PADDING :) ###########################################################
// #############################################################################