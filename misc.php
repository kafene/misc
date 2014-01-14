<?php

// #############################################################################
// #############################################################################
// #############################################################################

function event($name, $value = null) {
    static $events = [];

    if (false === $name) {
        unset($events[$value]);
        return;
    }

    $name = strtolower($name);

    if ($name && is_callable($value)) {
        return $events[$name][] = $value;
    } elseif ($name && isset($events[$name])) {
        foreach($events[$name] as $callback) {
            $callback($value);
        }

        return $value;
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

class DB {
    protected $pdo;

    function __construct(\PDO $pdo) {
        $this->pdo = $pdo;
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    function &getConnection() {
        return $this->pdo;
    }

    function prequery(\PDO $db, $sql) {
        if (func_num_args() < 3) {
            return $db->query($sql);
        }

        $stmt = $db->prepare($sql);
        $stmt->execute(array_slice(func_get_args(), 2));
        return $stmt;
    }

    function __call($method, $args) {
        return call_user_func_array([$this->pdo, $method], $args);
    }

    function escape($value) {
        $value = str_replace(['\\',"\0" ,'`'], '', $value);
        // $value = preg_replace('/[^A-Za-z0-9_.-]/', '', $value);
        return $i;
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

function server($key) {
    foreach (["ORIG_$key", "REDIRECT_$key", $key] as $key) {
        if (!empty($_SERVER[$key])) {
            return $_SERVER[$key];
        }
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

function enable_cors($enable) {
    if (false === $enable) {
        header_remove("Access-Control-Allow-Origin");
    } else {
        header("Access-Control-Allow-Origin: *");
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

# Find files recursively in a given directory
# Filtered by a regular expression pattern
function rscandir($dir, $filter_pattern = '/.*/') {
    if (!is_dir($dir = realpath($dir))) {
        return [];
    }

    $df = \FilesystemIterator::KEY_AS_PATHNAME
        | \FilesystemIterator::CURRENT_AS_FILEINFO
        | \FilesystemIterator::SKIP_DOTS
        | \FilesystemIterator::UNIX_PATHS;
        #| \FilesystemIterator::FOLLOW_SYMLINKS;
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

// #############################################################################
// #############################################################################
// #############################################################################

# Recursively remove a directory
function remove_directory($path) {
    if (is_link($path)) {
        return unlink($path);
    }

    foreach (new \RecursiveDirectoryIterator($path) as $file) {
        if (in_array($f->getFilename(), ['.', '..'])) {
            continue;
        }

        if ($file->isLink()) {
            unlink($file->getPathName());
            continue;
        }

        if ($file->isFile()) {
            unlink($file->getRealPath());
            continue;
        }

        if ($file->isDir()) {
            remove_dir($file->getRealPath());
        }
    }

    return rmdir($path);
}

// #############################################################################
// #############################################################################
// #############################################################################

# Get the UNIX file permissions for a file, e.g. 0644, 0755
function file_permissions($file) {
    return substr(sprintf('%o', fileperms($file)), -4);
}

// #############################################################################
// #############################################################################
// #############################################################################

# PHP lacks a str_putcsv function despite having str_getcsv
# and fgetcsv/fputcsv. This uses an in-memory file handle and
# fputcsv to simulate str_putcsv.
if (!function_exists('str_putcsv')) {
    function str_putcsv(array $fields, $delimiter = ',', $enclosure = '"') {
        $fp = new \SplFileObject("php://memory", "r+");
        $csv = "";
        $fp->fputcsv($fields, $delimeter, $enclosure);
        $fp->fseek(0);
        while (!$fp->eof() && ($line = $fp->getCurrentLine())) {
            $csv .= trim($line).PHP_EOL;
        }
        return trim($csv);
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

function parse_xml($input) {
    if (class_exists('SimpleXMLElement')) {
        try {
            $elbackup = libxml_disable_entity_loader(true);
            $iebackup = libxml_use_internal_errors(true);
            $result = new \SimpleXMLElement($input);
            libxml_disable_entity_loader($elbackup);
            libxml_use_internal_errors($iebackup);
            return $result;
        } catch (\Exception $e) {
        }
    }
    return $input;
}

// #############################################################################
// #############################################################################
// #############################################################################

function sqlite_session_handler_init(\PDO $Q, $T = 'php_session') {
    $Q->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    $T = sprintf("`%s`", str_replace(["\"","'","`"], "_", $T));
    return session_set_save_handler(function ($path, $name) use ($Q, $T) {
        $cols = "id TEXT PRIMARY KEY,data TEXT,time INTEGER";
        return $Q->query("CREATE TABLE IF NOT EXISTS {$T} ($cols);");
    }, function () {
        return true;
    }, function ($id) use ($Q, $T) {
            $s = $Q->prepare("SELECT data FROM {$T} WHERE id=? LIMIT 1");
            $s->execute((string) $id);
            $v = $s->fetchColumn();
            $s->closeCursor();
            return $v ? base64_decode($v) : null;
    }, function ($id, $v) use ($Q, $T) {
            $s = $Q->prepare("REPLACE INTO {$T} (data,time,id) VALUES(?,?,?)");
            return $s->execute([base64_encode($v), time(), (string) $id]);
    }, function ($id) use ($Q, $T) {
            $s = $Q->prepare("DELETE FROM {$T} WHERE id=?");
            return $s->execute([(string) $id]);
    }, function ($max) use ($Q, $T) {
            $s = $Q->prepare("DELETE FROM {$T} WHERE time<?");
            return $s->execute([(int) (time() - $max)]);
    });
}

// #############################################################################
// #############################################################################
// #############################################################################

# Change base of a number from one base to another
# Without GMP, the maximum base_convert supports is 32
function rebase($n, $from = 10, $to = 62) {
    return ($from > 32 || $to > 32)
        ? gmp_strval(gmp_init($n, $from), $to)
        : base_convert($n, $from, $to);
}

// #############################################################################
// #############################################################################
// #############################################################################

function create_iv($expires, $secret) {
    $a = hash_hmac('sha1', 'a'.$expires.'b', $secret);
    $b = hash_hmac('sha1', 'z'.$expires.'y', $secret);
    return pack("h*", $a.$b);
}

// #############################################################################
// #############################################################################
// #############################################################################

class Aes256 {
    static function encrypt($data, $key) {
        $key = mb_substr($key, 0, 32);
        $iv = mb_substr(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM), 0, 32);
        $data = mcrypt_encrypt('rijndael-256', $key, $data, 'cbc', $iv);
        return sprintf('%s|%s', base64_encode($data), base64_encode($iv));
    }
    static function decrypt($data, $key) {
        list($data, $iv) = array_map('base64_decode', explode('|', $data));
        list($key, $iv) = [mb_substr($key, 0, 32), mb_substr($iv, 0, 32)];
        $data = mcrypt_decrypt('rijndael-256', $key, $data, 'cbc', $iv);
        return str_replace("\x0", '', $data);
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

function json_htmlencode($obj) {
    // Encode <, >, ', &, and ", RFC4627 JSON, for embedding in HTML.
    $flags = JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT;
    return json_encode($obj, $flags);
}

// #############################################################################
// #############################################################################
// #############################################################################

# Similar to PHP's own trim() function, except when using extra
# characters to trim, it will append those to the default trim
# characters instead of replacing the defaults with the new one.
function trim_extra($str, $chars = '') {
    return trim($str, chr(32).chr(9).chr(10).chr(13).chr(0).chr(11).$chars);
}

// #############################################################################
// #############################################################################
// #############################################################################

# String sanitizer
function sanitize($string, $entities = false) {
    $encode_flags = ENT_HTML5|ENT_QUOTES|ENT_SUBSTITUTE; #|ENT_DISALLOWED;
    $string = filter_var($string, FILTER_SANITIZE_STRING);
    $fn = $entities ? 'htmlentities' : 'htmlspecialchars';
    return $fn($string, $encode_flags, 'UTF-8', false);
}

// #############################################################################
// #############################################################################
// #############################################################################

function apply(callable $callable, array $args = array()) {
    return call_user_func_array($callable, $args);
}
function call(callable $callable) {
    return apply($callable, array_slice(func_get_args(), 1));
}

// #############################################################################
// #############################################################################
// #############################################################################

# Get the class "basename" of the given object / class.
function class_basename($class) {
    $class = is_object($class) ? get_class($class) : $class;
    return basename(strtr($class, '\\', '/'));
}

// #############################################################################
// #############################################################################
// #############################################################################

function str_linkify($str) {
    return preg_replace('#(https?://\w[-_./\w]+)#i', '<a href="$1">$1</a>', $str);
}

// #############################################################################
// #############################################################################
// #############################################################################

function slug($str, $slug = '-') {
    if (function_exists('iconv')) {
        $str = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $string);
    } else {
        $tstr = htmlentities($str, ENT_QUOTES, 'UTF-8');
        if (false !== strpos($tstr, '&')) {
            $r = '/&([a-z]{1,2})(?:acute|caron|cedil|circ|grave|lig|orn|ring|slash|tilde|uml);/i';
            $str = html_entity_decode(preg_replace($r, '$1', $tstr), ENT_QUOTES, 'UTF-8');
        }
    }

    return strtolower(trim(preg_replace('/\W+/i', $slug, $str), $slug));
}

// #############################################################################
// #############################################################################
// #############################################################################

function size_format($bytes, $precision = 2, $format = '%-7.2f %s') {
    $u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
    $p = floor((($b = max($bytes, 0)) ? log($b) : 0) / log(1024));
    $b /= (1 << (10 * ($p = min($p, count($u) - 1))));
    return sprintf($format, round($b, $precision), $u[$p]);
}

// #############################################################################
// #############################################################################
// #############################################################################

class Path {
    static function normalize($path) {
        $path = strtr($path, '\\', '/');
        $path = preg_replace('/^[A-Za-z]:/', '', $path);
        $path = preg_replace("/[\/](?!<:\/)+/", '/', $path);
        return $path;
    }

    static function join() {
        $args = array_filter(func_get_args());
        foreach ($args as &$arg) {
            $arg = trim($arg, '/');
        }

        return trim(static::normalize(join('/', $args)));
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

class CSRF {
    static function getToken($expires = 600) {
        session_id() or session_start();

        if (empty($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = array();
        }

        $nonce = hash('sha256', mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));
        $ip = (string) $_SERVER['REMOTE_ADDR'];
        $ttl = $expires ? (time() + (int) $expires) : 0;
        $_SESSION['csrf_tokens'][$nonce] = compact('ip', 'ttl');

        return $nonce;
    }

    static function validateToken($token) {
        session_id() or session_start();

        if (!empty($token) && !empty($_SESSION['csrf_tokens'][$token])) {
            $found = $_SESSION['csrf_tokens'][$token];
            unset($_SESSION['csrf_tokens'][$token]);

            if (isset($found['ip'], $found['ttl']) &&
                ($_SERVER['REMOTE_ADDR'] == $found['ip']) &&
                (0 == $found['ttl'] || time() < $found['ttl']))
            {
                return true;
            }
        }

        session_regenerate_id();
        return false;
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

function is_iterable($var) {
    set_error_handler(function ($n, $s, $f, $l) {
        throw new \ErrorException($s, null, $n, $f, $l);
    });

    try {
        foreach ($var as $v) {
            break;
        }
    } catch(\ErrorException $e) {
        restore_error_handler();
        return false;
    }

    restore_error_handler();
    return true;
}

// #############################################################################
// #############################################################################
// #############################################################################

# Shortcut define or get constant if defined
function def($name, $value = null) {
    if (null === $value) {
        return defined($name) ? constant($name) : null;
    }

    defined($k) or define($k, $v);
    return constant($k);
}

// #############################################################################
// #############################################################################
// #############################################################################

function log_write($message, $severity = LOG_DEBUG) {
    if (!filter_var(ini_get('log_errors', FILTER_VALIDATE_BOOLEAN))) {
        return;
    }

    $inilog = ini_get('error_log');
    $file = (is_string($inilog) && !empty($inilog)) ? $inilog : 'php://stderr';
    $severity = addcslashes(strval($severity), '"');
    $message = addcslashes(strval($message), '"')."\n";
    $line = sprintf('"%s", "%s", "%s"', time(), $severity, $message);

    return error_log($line, 3, $file);
}

// #############################################################################
// #############################################################################
// #############################################################################

function get_request_method($allow_override = true) {
    if ($allow_override) {
        if (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
            $method = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'];
        } elseif (isset($_POST['_method'])) {
            $method = $_POST['_method'];
        } elseif (isset($_POST['_METHOD'])) {
            $method = $_POST['_METHOD'];
        }
    }

    if (empty($method)) {
        $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
    }

    return strtoupper($method);
}

// #############################################################################
// #############################################################################
// #############################################################################

function is_ascii($string) {
    return !preg_match('/[^\x00-\x7F]/S', $string);
}

// #############################################################################
// #############################################################################
// #############################################################################

# Validate URL with optional DNS record check
function is_url($url, $check_dns = false) {
    $valid = is_string(filter_var($url, FILTER_VALIDATE_URL));

    if ($check_dns) {
        $valid = $valid && false !== checkdnsrr($url, 'ANY');
    }

    return $valid;
}

// #############################################################################
// #############################################################################
// #############################################################################

# Validate email with optional MX Record check
function is_email($email, $check_mx = false) {
    $valid = is_string(filter_var($email, FILTER_VALIDATE_EMAIL));

    if ($check_mx) {
        $valid = $valid && getmxrr(ltrim(strrchr($email, '@'), '@'), $x);
    }

    return $valid;
}

// #############################################################################
// #############################################################################
// #############################################################################

function session_started() {
    return PHP_SESSION_ACTIVE === session_status();
}

// #############################################################################
// #############################################################################
// #############################################################################

function is_https() {
    return filter_var(getenv('HTTPS'), FILTER_VALIDATE_BOOLEAN);
}

// #############################################################################
// #############################################################################
// #############################################################################

function get_base_uri()  {
    $request_uri = getenv('REQUEST_URI') ?: getenv('PHP_SELF');
    $script_name = getenv('SCRIPT_NAME') ?: null;
    $base_uri = strpos($request_uri, $script_name) === 0
        ? $script_name
        : strtr(dirname($script_name), '\\', '/');

    return rtrim($base_uri, '/');
}

// #############################################################################
// #############################################################################
// #############################################################################

# PHP (5.4+) only allows *one* callback to be registered, which is executed
# before the headers are sent. This allows setting an unlimited number.
function header_callback(callable $callback = null, $prepend = false) {
    static $callbacks = array();
    static $registered = false;

    # Dispatch the callbacks
    if (0 === func_num_args()) {
        if (headers_sent()) {
            throw new \UnexpectedValueException("Headers have already been sent?!");
        }

        foreach ($callbacks as $callback) {
            $callback();
        }

        return;
    }

    if ($prepend) {
        array_unshift($callbacks, $callback);
    } else {
        $callbacks[] = $callback;
    }

    if (!$registered) {
        header_register_callback('header_callback');
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

/**
 * This takes a string and trims off start and ending pairs (brackets)
 * E.g., "[(Something)]" => "Something", "[[[[[]]]]]" => ""
 * Don't ask me why I used an anonymous function and a while loop, I just did.
 *
 * @param string $str
 * @return string
 */
function trim_bounds($str) {
    $str = trim($str);
    if (strlen($str) < 2) {
        return $str;
    }
    $tf = function (&$c) {
        $c = trim($c);
        $fc = $c[0];
        $lc = $c[strlen($c) - 1];
        if (
            ('[' === $fc && ']' === $lc) ||
            ('{' === $fc && '}' === $lc) ||
            ('<' === $fc && '>' === $lc) ||
            ('(' === $fc && ')' === $lc) ||
            ('^' === $fc && '$' === $lc) ||
            ($fc === $lc && !ctype_alnum($fc))
        ) {
            $c = substr($c, 1, strlen($c) - 2);
            return true;
        }
    };
    while ($tf($str));
    return $str;
}

// #############################################################################
// #############################################################################
// #############################################################################

function cycle() {
    static $i;
    return func_get_args()[($i++%func_num_args())];
}
# for ($i = 0; $i < 10; $i++) var_dump(cycle('1', '2', '3'));

// #############################################################################
// #############################################################################
// #############################################################################

# Replace all of {{these}} with $vars['these']
function brace($path, array $vars = []) {
    return str_replace(
        array_map(function ($v) {
            return sprintf('{{%s}}', $v);
        }, array_keys($vars)),
        array_values($vars),
        file_get_contents(realpath($path))
    );
}

// #############################################################################
// #############################################################################
// #############################################################################

# Finds comments... in a file.
function find_comments($file) {
    $contents = file_get_contents($file);
    $regex = '/\/\*(?<!(\*\/))(.*)(?!(\*\/))\/\*/msSU';
    return preg_match_all($regex, $contents, $matches)
        ? array_map(function ($comment) {
            return join('', array_filter(array_map(function ($line) {
                return ltrim($line, "\r\n\t\0 */");
            }, explode("\n", $comment))));
        }, $matches[2])
        : [];
}

// #############################################################################
// #############################################################################
// #############################################################################

function noise($len = 32) {
    return substr(str_shuffle(str_repeat(join('', range('!','~')), 3)), 0, $len);
}

// #############################################################################
// #############################################################################
// #############################################################################

function rss($title, $link, array $entries) {
    while (ob_get_level()) ob_end_clean();
    header("Content-Type: application/rss+xml;charset=UTF-8")
    print '<?xml version="1.0" encoding="UTF-8"?>';
    print '<rss version="2.0">';
    print '<channel>';
    print '<title>'.$title.'</title>';
    print '<link>'.$link.'</link>';
    print '<description>'.$title.' [RSS]</description>';
    foreach ($items as $item) {
        print '<item>';
        print '<title>'.$item['title'].'</title>';
        print '<link>'.$item['link'].'</link>';
        print '<pubDate>'.gmdate(DATE_RSS, $item['time']).' GMT</pubDate>';
        print '</item>';
    }
    print '</channel>';
    print '</rss>';
    exit;
}

// #############################################################################
// #############################################################################
// #############################################################################

# Determine if an IP is in a subnet
# http://stackoverflow.com/questions/594112
# E.g. ip_cidr_match('65.40.32.4', '65.40.0.0/64') == true
function ip_cidr_match($ip, $other) {
    $ip = (string) $ip;
    $other = (string) $other;
    if (false !== strpos($other, '/')) {
        list($subnet, $mask) = explode('/', $other);
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        $subnet &= $mask;
        return ($ip & $mask) == $subnet;
    } else {
        return $ip == $other;
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

function http_date($dt = 0) {
    $time = ($dt && is_int($dt)) ? $dt : time();
    return gmdate("D, d M Y H:i:s", $time).' GMT';
}

// #############################################################################
// #############################################################################
// #############################################################################

function copy_directory_structure($src, $dest) {
    // This assumes an empty directory.
    $dh = opendir($src);
    $ds = DIRECTORY_SEPARATOR;

    while ($d = readdir($dh)) {
        if (is_dir($src.$ds.$d) && $d != '.' && $d != '..') {
            mkdir($dest.$ds.$d);
            copy_directory_structure($src.$ds.$d, $dest.$ds.$d);
        }
    }

    return closedir($dh);
}

// #############################################################################
// #############################################################################
// #############################################################################

class UUID {
    static function validate($uuid) {
        $pattern = "/^\{?[0-9a-f]{8}-?[0-9a-f]{4}-?4[0-9a-f]{3}-?[89ab][0-9a-f]{3}-?[0-9a-f]{12}\}?$/";
        return 1 === preg_match($pattern, strtolower($uuid));
    }
    static function generate() {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff)
        );
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

class Bcrypt {
    static $base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    static $bcryptchars = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    static function hash($password, $cost = 14) {
        if (!is_string($password) || !is_int($cost) || $cost < 4 || $cost > 31) {
            throw new \InvalidArgumentException();
        }

        $salt = base64_encode(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        $salt = rtrim($salt, '=');
        $salt = strtr($salt, self::$base64chars, self::$bcryptchars);
        $salt = mb_substr($salt, 0, 22, '8bit');
        $hash = sprintf("$2y$%02d$%s", $cost, $salt);
        $hash = crypt($password, $hash);

        return (is_string($hash) && 60 === mb_strlen($hash, '8bit')) ? $hash : false;
    }

    static function verify($password, $hash) {
        $crypt = crypt($password, $hash);
        $hl = mb_strlen($hash, '8bit');
        $cl = mb_strlen($crypt, '8bit');

        if (!is_string($crypt) || $cl !== $hl || $cl <= 13) {
            return false;
        }

        $status = 0;
        for ($i = 0; $i < $cl; $i++) {
            $status |= (ord($crypt[$i]) ^ ord($hash[$i]));
        }

        return 0 === $status;
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

function slow_equals($known_value, $user_input) {
    /* Prevent issues if string length is 0. */
    $known_value .= chr(0);
    $user_input .= chr(0);
    $klen = strlen($known_value);
    $ulen = strlen($user_input);
    $result = $klen - $ulen;

    for ($i = 0; $i < $ulen; $i++) {
        $result |= (ord($known_value[$i % $klen]) ^ ord($user_input[$i]));
    }

    return $result === 0;
}

// #############################################################################
// #############################################################################
// #############################################################################

# ob_start('ob_etag_handler')
function ob_etag_handler($content, $bits) {
    static $buffer = '', $request_etag;

    if (!$request_etag && isset($_SERVER['HTTP_IF_NONE_MATCH'])) {
        $request_etag = strtolower(trim($_SERVER['HTTP_IF_NONE_MATCH'], "\"'"));
    }

    if (!($bits & PHP_OUTPUT_HANDLER_END)) {
        $buffer .= $content;
        return '';
    }

    $local = $buffer.$content;
    $buffer = '';
    $etag = md5($local);

    if ($etag === $request_etag) {
        header('HTTP/1.1 304 Not Modified', true, 304);
        return '';
    }

    header(sprintf('ETag: "%s"', $etag));
    return $local;
}

// #############################################################################
// #############################################################################
// #############################################################################

function glob_recursive($pattern, $flags = 0) {
    $files = glob($pattern, $flags);
    foreach (glob(dirname($pattern).'/*', GLOB_ONLYDIR | GLOB_NOSORT) as $dir) {
        $files = array_merge(
            $files,
            glob_recursive($dir.'/'.basename($pattern), $flags)
        );
    }
    return $files;
}

// #############################################################################
// #############################################################################
// #############################################################################

// Shim for latest PHP JSON constants/errors
// https://github.com/php/php-src/blob/master/ext/json/JSON_parser.h
// https://github.com/php/php-src/blob/master/ext/json/json.c
defined("JSON_ERROR_NONE") or define("JSON_ERROR_NONE", 0);
defined("JSON_ERROR_DEPTH") or define("JSON_ERROR_DEPTH", 1);
defined("JSON_ERROR_STATE_MISMATCH") or define("JSON_ERROR_STATE_MISMATCH", 2);
defined("JSON_ERROR_CTRL_CHAR") or define("JSON_ERROR_CTRL_CHAR", 3);
defined("JSON_ERROR_SYNTAX") or define("JSON_ERROR_SYNTAX", 4);
defined("JSON_ERROR_UTF8") or define("JSON_ERROR_UTF8", 5);
defined("JSON_ERROR_RECURSION") or define("JSON_ERROR_RECURSION", 6);
defined("JSON_ERROR_INF_OR_NAN") or define("JSON_ERROR_INF_OR_NAN", 7);
defined("JSON_ERROR_UNSUPPORTED_TYPE") or define("JSON_ERROR_UNSUPPORTED_TYPE", 8);
if (!function_exists("json_last_error_msg")) {
    function json_last_error_msg() {
        switch (json_last_error()) {
            case JSON_ERROR_NONE:
                return "No error";
            case JSON_ERROR_DEPTH:
                return "Maximum stack depth exceeded";
            case JSON_ERROR_STATE_MISMATCH:
                return "State mismatch (invalid or malformed JSON)";
            case JSON_ERROR_CTRL_CHAR:
                return "Control character error, possibly incorrectly encoded";
            case JSON_ERROR_SYNTAX:
                return "Syntax error";
            case JSON_ERROR_UTF8:
                return "Malformed UTF-8 characters, possibly incorrectly encoded";
            case JSON_ERROR_RECURSION:
                return "Recursion detected";
            case JSON_ERROR_INF_OR_NAN:
                return "Inf and NaN cannot be JSON encoded";
            case JSON_ERROR_UNSUPPORTED_TYPE:
                return "Type is not supported";
            default:
                return "Unknown error";
        }
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

function json_safe_encode($obj, $callback = null) {
    $flags = JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT;
    $encoded = json_encode($obj, $flags);

    if (JSON_ERROR_NONE !== ($jle = json_last_error())) {
        throw new \InvalidArgumentException(json_last_error_msg());
    }

    if (null !== $callback) {
        // http://www.geekality.net/2011/08/03/valid-javascript-identifier/
        $pattern = '/^[$_\p{L}][$_\p{L}\p{Mn}\p{Mc}\p{Nd}\p{Pc}\x{200C}\x{200D}]*+$/u';
        $parts = explode('.', $callback);

        foreach ($parts as $part) {
            if (!preg_match($pattern, $part)) {
                throw new \InvalidArgumentException("Invalid callback name.");
            }
        }

        $encoded = sprintf("%s(%s);", $callback, $encoded);
    }

    return $encoded;
}

// #############################################################################
// #############################################################################
// #############################################################################

// #############################################################################
// #############################################################################
// #############################################################################
