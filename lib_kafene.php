<?php

# Hashcash is a computationally expensive operation for the sender, while being
# easily verified by the receiver. It proves this email was worth working for
# and isn't spam. From - http://github.com/Xeoncross/kit
function hashcash($email) {
    $count = 0;
    $hashcash = sprintf('1:20:%u:%s::%u', date('ymd'), $email, mt_rand());
    while(strncmp('00000', sha1($hashcashc.$count), 5) !== 0) { ++$count; }
    return $hashcash.$count;
}


# Event Handler
function event($name = null, $value = null) {
    static $events = [];
    # Name should be case insensitive.
    $name = strtolower(basename($name));
    # Get all - event();
    if(0 === func_num_args()) {
        return $events;
    }
    # Remove by name - event('myevent', false);
    elseif($name && false === $value) {
        unset($events[$name]);
    }
    # Remove all - event(false);
    elseif(empty($name) && null === $value) {
        $events = [];
    }
    # Attach event - event('myevent', $func);
    elseif(is_a($value, 'Closure')) {
        $events[$name][] = $value;
    }
    # Fire event - event('myevent'), event('myevent', ['arg1', 'arg2']);
    elseif($name && (is_array($value) || null === $value)) {
        if(!is_array($value)) {
            $value = [];
        }
        foreach(ifsetor($events[$name], []) as $fn) {
            if(is_array($result = call_user_func_array($fn, $value))) {
                $value = $result;
            }
        }
        return $value;
    }
}


# Find files recursively in a given directory
# Filtered by a regular expression pattern
function rscandir($dir, $filter_pattern = '/.*/') {
    if(!is_dir($dir)) { return []; }
    $df = \FilesystemIterator::KEY_AS_PATHNAME
        | \FilesystemIterator::CURRENT_AS_FILEINFO
        | \FilesystemIterator::SKIP_DOTS
        | \FilesystemIterator::UNIX_PATHS;
    # | \FilesystemIterator::FOLLOW_SYMLINKS;
    $rf = \RecursiveIteratorIterator::SELF_FIRST
        | \RecursiveIteratorIterator::CATCH_GET_CHILD;
    $rd = new \RecursiveDirectoryIterator($dir, $df);
    $it = new \RecursiveIteratorIterator($rd, $rf);
    $rx = new \RegexIterator($it, $filter_pattern);
    $found = iterator_to_array($rx);
    $files = array_filter(array_keys($found), 'is_file');
    $files = array_intersect_key($found, array_flip($files));
    return $files;
}


# Recursively remove a directory
function remove_dir($path) {
    if(is_link($path)) {
        return unlink($path);
    }
    foreach(new \RecursiveDirectoryIterator($path) as $file) {
        if(in_array($f->getFilename(), ['.', '..'])) {
            continue;
        }
        if($file->isLink()) {
            unlink($file->getPathName());
            continue;
        }
        if($file->isFile()) {
            unlink($file->getRealPath());
            continue;
        }
        if($file->isDir()) {
            remove_dir($file->getRealPath());
        }
    }
    return rmdir($path);
}


# Get the UNIX file permissions for a file, e.g. 0644, 0755
function file_permissions($file) {
    return substr(sprintf('%o', fileperms($file)), -4);
}


# PHP lacks a str_putcsv function despite having str_getcsv
# and fgetcsv/fputcsv. This uses an in-memory file handle and
# fputcsv to simulate str_putcsv.
if(!function_exists('str_putcsv')) {
    function str_putcsv($input, $delimiter = ',', $enclosure = '"') {
        $fh = fopen('php://temp', 'r+');
        fputcsv($fh, $input, $delimiter, $enclosure);
        rewind($fh);
        $data = fread($fh, 1048576);
        fclose($fh);
        return rtrim($data, "\n");
    }
}


# Change base of a number from one base to another
# Without GMP, the maximum base_convert supports is 32
function rebase($n, $from = 10, $to = 62) {
    return ($from > 32 || $to > 32)
        ? gmp_strval(gmp_init($n, $from), $to)
        : base_convert($n, $from, $to);
}


function get_iv($expires, $secret) {
    $a = hash_hmac('sha1', 'a'.$expires.'b', $secret);
    $b = hash_hmac('sha1', 'z'.$expires.'y', $secret);
    return pack("h*", $a.$b);
}


# Timing safe string comparison
function slow_equals($a, $b) {
    $diff = strlen($a) ^ strlen($b);
    for($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
        $diff |= ord($a[$i]) ^ ord($b[$i]);
    }
    return 0 === $diff;
}


function encrypt($data, $key, $algo = 'rijndael-256', $mode = 'cbc', $dev = MCRYPT_DEV_URANDOM) {
    return sprintf('%s|%s', base64_encode(mcrypt_encrypt(
        $algo,
        mb_substr($key, 0, mcrypt_get_key_size($algo, $mode)),
        $data,
        $mode,
        $iv = mb_substr(mcrypt_create_iv(
            $z = mcrypt_get_iv_size($algo, $mode),
            $dev
        ), 0, $z)
    )), base64_encode($iv));
}


function decrypt($data, $key, $algo = 'rijndael-256', $mode = 'cbc') {
    list($data, $iv) = array_map('base64_decode', explode('|', $data));
    return str_replace("\x0", '', mcrypt_decrypt(
        $algo,
        mb_substr($key, 0, mcrypt_get_key_size($algo, $mode)),
        $data,
        $mode,
        mb_substr($iv, 0, mcrypt_get_iv_size($algo, $mode))
    ));
}


if(!function_exists('password_hash')) {
    function password_hash($password, $rounds = 12) {
        $rounds = ($rounds < 4 ? 4 : ($rounds > 31 ? 31 : $rounds));
        $nonce = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);
        $nonce = substr(strtr(base64_encode($crypt), '+', '.'), 0, 22);
        $crypt = crypt($password, sprintf('$2y$%02d$%s', $rounds, $nonce));
        return (is_string($crypt) && strlen($crypt) >= 60) ? $crypt : false;
    }
    function password_verify($password, $hash) {
        $r = crypt($password, $hash);
        if(!is_string($r) || strlen($r) != strlen($hash) || strlen($r) < 60) {
            return false;
        }
        for($i = 0, $j = 0; $i < strlen($r); $i++)
            $j |= (ord($r[$i]) ^ ord($hash[$i]));
        return $j === 0;
    }
}


function json_htmlencode($obj) {
    // Encode <, >, ', &, and ", RFC4627 JSON, for embedding in HTML.
    $flags = JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT;
    return json_encode($obj, $flags);
}


# Similar to PHP's own trim() function, except when using extra
# characters to trim, it will append those to the default trim
# characters instead of replacing the defaults with the new one.
function trim_extra($str, $chars = '') {
    $chars = chr(32).chr(9).chr(10).chr(13).chr(0).chr(11).$chars;
    return trim($str, $chars);
}


# Rev:20100913_0900 - https://github.com/jmrware/LinkifyURL
function linkify($text, $html = true) {
    static $url_pattern = '/
        (\()((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\))|
        (\[)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\])|
        (\{)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\})|
        (<|&(?:lt|\#60|\#x3c);)
        ((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)
        (>|&(?:gt|\#62|\#x3e);)|((?:^|[^=\s\'"\]])\s*[\'"]?|[^=\s]\s+)
        (\b(?:ht|f)tps?:\/\/[a-z0-9\-._~!$\'()*+,;=:\/?#[\]@%]+(?:
        (?!&(?:gt|\#0*62|\#x0*3e);|&(?:amp|apos|quot|\#0*3[49]|\#x0*2[27]);
        [.!&\',:?;]?(?:[^a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]|$))
        &[a-z0-9\-._~!$\'()*+,;=:\/?#[\]@%]*)*[a-z0-9\-_~$()*+=\/#[\]@%])
    /imx';
    static $section_html_pattern = '%
        ([^<]+(?:(?!<a\b)<[^<]*)*|(?:(?!<a\b)<[^<]*)+)|
        (<a\b[^>]*>[^<]*(?:(?!</a\b)<[^<]*)*</a\s*>)
    %ix';
    static $url_replace = '$1$4$7$10$13<a href="$2$5$8$11$14">$2$5$8$11$14</a>$3$6$9$12';
    return ($html)
        ? preg_replace_callback($section_html_pattern, function($m) {
              return isset($m[2]) ? $m[2] : linkify($m[1], false);
          }, preg_replace('/&apos;/', '&#39;', $text));
        : preg_replace($url_pattern, $url_replace, $text);
}


# String sanitizer
function h($str, $entities = false) {
  $flags = FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH;
  $str = filter_var($str, FILTER_SANITIZE_STRING, $flags);
  $str = preg_replace('/\p{C}+/um', '', $str); // strip control chars
  $flags = ENT_HTML5 | ENT_QUOTES | ENT_SUBSTITUTE | ENT_DISALLOWED;
  $fn = $ent ? 'htmlentities' : 'htmlspecialchars';
  return $fn($str, $flags, 'UTF-8', false);
}


# Get the class "basename" of the given object / class.
function class_basename($class) {
    $class = is_object($class) ? get_class($class) : $class;
    return basename(strtr($class, '\\', '/'));
}


function str_linkify($str) {
    return preg_replace('#(https?://\w[-_./\w]+)#i', '<a href="$1">$1</a>', $str);
}


# Regular expression array key search
function from(array $source, $key = null, $default = null, $limit = true) {
    $source = (array) $source;
    if(null === $key) { return $source; }
    if(array_key_exists($key, $source)) { return $source[$key]; }
    $keys = array_keys($source);
    $grep = preg_grep("~^($key)$~i", $keys);
    $out = array_intersect_key($source, array_flip($grep));
    return empty($out) ? $default : ($limit ? end($out) : $out);
}


# Check if $array keys are exactly the same as $keys_need
function array_keys_equal(array $array, array $keys_need, $strict = true) {
    $keys_have = array_keys($array);
    ksort($keys_need);
    ksort($keys_have);
    return ($strict)
        ? ($keys_need === $keys_have)
        : ($keys_need == $keys_have);
}


# Check if all of the keys from $keys are in the keys of $array
function array_keys_exist(array $array, array $keys) {
    $keys = array_flip($keys);
    $diff = array_diff_key($keys, $array);
    return empty($diff);
}


# Convert XML to an array
function array_from_xml($xml) {
    $xml = simplexml_load_string($xml);
    $xml = json_encode($xml);
    return json_decode($xml, true);
}


# Get all of items from $a that don't have keys in $keys
function array_except(array $array, $keys) {
    return array_diff_key($array, array_flip((array) $keys));
}


# Get a only items from the array with keys specified in $keys
function array_only($a, $keys) {
    return array_intersect_key($a, array_flip((array) $keys));
}


function is_iterable($var) {
    set_error_handler(function($n, $s, $f, $l) {
        throw new \ErrorException($s, null, $n, $f, $l);
    });
    try {
        foreach($var as $v) break;
    } catch(\ErrorException $e) {
        restore_error_handler();
        return false;
    }
    restore_error_handler();
    return true;
}


function array_transpose(array $array) {
    array_unshift($array, null);
    return call_user_func_array('array_map', $array);
}


function log_write($message, $severity = LOG_DEBUG, $file = ) {
    if(!filter_var(ini_get('log_errors', FILTER_VALIDATE_BOOLEAN))) return;
    $file = ini_get('error_log') ?: 'php://stderr';
    $severity = addcslashes(strval($severity), '"');
    $message = addcslashes(strval($message), '"')."\n";
    $line = sprintf('"%s", "%s", "%s"', time(), $severity, $message);
    return error_log($line, $file ? 3 : 0, $file);
}


function get_request_method($allow_override = true) {
    if($allow_override) {
        $post = array_change_key_case($_POST, CASE_LOWER);
        if(isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
            $method = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'];
        } elseif(isset($post['_method'])) {
            $method = $post['_method'];
        }
    }
    if(empty($method)) {
        $method = isset($_SERVER['REQUEST_METHOD'])
            ? $_SERVER['REQUEST_METHOD']
            : 'GET';
    }
    return strtolower($method);
}


function is_ascii($str) {
    return !preg_match('/[^\x00-\x7F]/S', $str);
}

function url($url, $dns = false) {
    return is_string(filter_var($url, FILTER_VALIDATE_URL))
        && (!$dns || (false !== checkdnsrr($url, 'ANY')));
}

function is_email($str, $mx = false) {
    return is_string(filter_var($str, FILTER_VALIDATE_EMAIL))
        && (!$mx || getmxrr(ltrim(strrchr($str, '@'), '@'), $x));
}

function session_started() {
    $active = [PHP_SESSION_ACTIVE, PHP_SESSION_DISABLED];
    return in_array(session_status(), $active);
}

function is_https() {
    return filter_var(getenv('HTTPS'), FILTER_VALIDATE_BOOLEAN);
}


function get_base_uri()  {
    $request_uri = getenv('REQUEST_URI') ?: getenv('PHP_SELF');
    $script_name = getenv('SCRIPT_NAME') ?: null;
    $base_uri = strpos($request_uri, $script_name) === 0
        ? $script_name
        : strtr(dirname($script_name), '\\', '/');
    return rtrim($base_uri, '/');
}


# Simple key-value storage/cache
function c($key = null, $value = null) {
    static $_cache = [];
    $argc = func_num_args();
    if (0 === $argc) { # get all
        return $_cache;
    } elseif (is_array($key)) { # Set array of [key => val]
        foreach ($key as $k => $v) c($k, $v);
    } elseif (2 === $argc) { # Set key => val, or unset - c(false, key)
        if (false === $key) unset($_cache[$value]);
        else return $_cache[$key] = $value;
    } elseif (1 === $argc && $key) { # Get key if set
        return array_key_exists($key, $_cache) ? $_cache[$key] : null;
    }
}


# Replacement for PHP 5.4 header_register_callback until it's functional.
function header_callback(callable $callback = null, $priority = 0) {
    static $callbacks;
    if (null === $callbacks) {
        header_register_callback(__FUNCTION__);
        $callbacks = [];
    }
    if (0 === func_num_args()) {
        ksort($callbacks);
        array_map('call_user_func', $callbacks);
        return;
    } elseif ($priority) {
        $callbacks[(int) $priority] = $callback;
    } else {
        $callbacks[] = $callback;
    }
}

# Add a header string without writing an anonymous function to handle it:
function header_add($string) {
    $args = func_get_args();
    header_callback(function() use ($args) {
        header(call_user_func_array('sprintf', $args));
    });
}


# transform markdown to html
if (!function_exists('markdown')) {
function markdown($str) {
    $a = ["/\r?\n/", "/>/", "/\n{4,}/"];
    $b = ["\n", "&gt;", "\n\n\n"];
    $str = preg_replace($a, $b, stripslashes($str)."\n\n");
    $md = [
        "/\n+(&gt;\s{1}(.+))\n{2,}/i" => "<blockquote>$2</blockquote>\n",
        "/#+\s{1}(.+)\n+/i" => "<h3>$1</h3>\n",
        "/\((.+?)\)\[(\S+?)\]/i" => "<a href=\"$2\">$1</a>",
        "/\!\[(.+?)\]\((.+?)\)/i" => "<img src=\"$1\" alt=\"$2\">",
        "/\n{2,}(-\s{1}(.+)\n{1}.+)/im" => "\n<ul>$1",
        "/(-\s{1}(.+)\n)\n+/im" => "$1</ul>\n",
        "/\n?(-\s{1}(.+))\n?/i" => "<li>$2</li>",
        "/^(.+)\n+/i" => "<p>$1</p>\n",
        "/\n+(.+)[\n+\Z]?/im" => "<p>$1</p>\n",
    ];
    return preg_replace(array_keys($md), array_values($md), $str);
}
}




