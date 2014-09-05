<?php

// #############################################################################
// #############################################################################
// #############################################################################

# event('foo.bar', null, function () { echo 'foo.bar 1'; }); // add
# event('foo.bar', null, function () { echo 'foo.bar 2'; }); // add
# event('foo.bar'); // emit
# event('foo.bar', null, false); // remove
function event($event, array $args = null, $callback = null) {
    static $events = [];

    if ($callback !== null) {
        if ($callback) {
            $events[$event][] = $callback;
        } else {
            unset($events[$event]);
        }
    } elseif (isset($events[$event])) {
        foreach ($events[$event] as $fn) {
            $args = call_user_func_array($fn, $args);
        }

        return $args;
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
    $dir = realpath($dir);

    if (!is_dir($dir)) {
        return [];
    }

    $directoryIteratorFlags = (
        \FilesystemIterator::KEY_AS_PATHNAME |
        \FilesystemIterator::CURRENT_AS_FILEINFO |
        \FilesystemIterator::SKIP_DOTS |
        \FilesystemIterator::UNIX_PATHS
        #| \FilesystemIterator::FOLLOW_SYMLINKS
    );

    $recursiveIteratorFlags = (
        \RecursiveIteratorIterator::SELF_FIRST |
        \RecursiveIteratorIterator::CATCH_GET_CHILD
    );

    $it = new \RecursiveDirectoryIterator($dir, $directoryIteratorFlags);
    $it = new \RecursiveIteratorIterator($it, $recursiveIteratorFlags);
    $it = new \RegexIterator($it, $filter_pattern);

    $found = iterator_to_array($it);
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

/**
 * From <https://gist.github.com/johanmeiring/2894568>
 */
function str_putcsv($input, $delimiter = ',', $enclosure = '"') {
    // Open a memory "file" for read/write
    $fp = fopen('php://temp', 'r+');

    // write the $input array to the "file"
    fputcsv($fp, $input, $delimiter, $enclosure);

    // rewind the "file" so we can read what we just wrote
    rewind($fp);

    // read the entire line into a variable
    $data = fread($fp, 1048576);

    // close the "file"
    fclose($fp);

    // return the $data, with the trailing eol removed.
    return rtrim($data, "\n");
}

// #############################################################################
// #############################################################################
// #############################################################################

function parse_xml($input) {
    try {
        $flag = LIBXML_NOWARNING | LIBXML_NOERROR | LIBXML_NONET;
        return new \SimpleXMLElement($input, $flag);
    } catch (\Exception $e) {}
    return $input;
}

// #############################################################################
// #############################################################################
// #############################################################################

function encode_csv(array $input, $delimiter = ',', $enclosure = '"') {
    $fp = fopen('php://temp/maxmemory:8388608', 'r+');
    $i = 0;
    foreach ($input as $fields) {
        if ($i === 0) {
            fputcsv($fp, array_keys($fields), $delimiter, $enclosure);
            $i = 1;
        }
        fputcsv($fp, $fields, $delimiter, $enclosure);
    }
    $result = (string) stream_get_contents($fp, -1, 0);
    fclose($fp);
    return $result ? rtrim($result, "\n") : '';
}

// #############################################################################
// #############################################################################
// #############################################################################

function parse_csv($input) {
    $result = [];
    # $fp = fopen('data://text/plain;base64,'.base64_encode($input), 'r');
    $fp = fopen('php://memory', 'rw');
    fwrite($fp, $input);
    fseek($fp, 0);
    while (false !== ($data = fgetcsv($fp))) {
        $result[] = $data;
    }
    fclose($fp);
    return $result;
}

// #############################################################################
// #############################################################################
// #############################################################################

function parse_http_digest($digestHeader) {
    $required = [
        'nonce' => 1,
        'nc' => 1,
        'cnonce' => 1,
        'qop' => 1,
        'username' => 1,
        'uri' => 1,
        'response' => 1,
    ];
    $result = [];
    $digestHeader = preg_replace('/\s+/', ' ', $digestHeader);
    $keys = join('|', array_keys($required));
    $regex = '@('.$keys.')\s*=\s*(?:([\'"])([^\2]+?)\2|([^\s,]+))@';
    preg_match_all($regex, $digestHeader, $matches, PREG_SET_ORDER);
    foreach ($matches as $m) {
        $result[$m[1]] = $m[3] ?: $m[4];
        unset($required[$m[1]]);
    }
    return empty($required) ? $result : false;
}

// #############################################################################
// #############################################################################
// #############################################################################

function parse_query_string($input) {
    $result = [];
    if (extension_loaded('mbstring')) {
        mb_parse_str($input, $result);
    } else {
        parse_str($input, $result);
    }
    return $result;
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
function trim_extra($str, $charList = '') {
    return trim($str, " \t\n\r\0\x0B".$charList);
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

function apply(callable $fn, array &$args = []) {
    return call_user_func_array($fn, $args);
}

function call(callable $fn) {
    return call_user_func_array($fn, array_slice(func_get_args(), 1));
}

// #############################################################################
// #############################################################################
// #############################################################################

# Get the class "basename" of the given object / class.
function class_basename($class) {
    $class = is_object($class) ? get_class($class) : $class;
    return basename(str_replace('\\', '/', $class));
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
function ip_cidr_match($ip, $range) {
    list ($subnet, $bits) = explode('/', $range);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = (-1 << (32 - $bits)) & 4294967295;
    $subnet &= $mask;
    return ($ip & $mask) == $subnet;
}
/*
var_dump(
    ip_cidr_match('65.40.32.4', '65.40.0.0/64'),
    ip_cidr_match("1.2.3.4", "0.0.0.0/0"),
    ip_cidr_match("127.0.0.1", "127.0.0.1/32"),
    ip_cidr_match("127.0.0.1", "127.0.0.2/32"),
    ip_cidr_match('32.18.96.4', '0.0.0.0/0')
);
*/

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

# ✧ lowcarb / Minidown (super-light markdown parser)
# From https://github.com/phuu/lowcarb
function minidown($string) {
    $string = stripslashes($string)."\n\n";
    $string = preg_replace("/\r\n/i", "\n", $string);
    $string = preg_replace("/\r/i", "\n", $string);
    $string = preg_replace("/>/i", "&gt;", $string);
    $string = preg_replace("/\n{4,}/i", "\n\n\n", $string);
    $patterns = [
        "/\n+(&gt;\s{1}(.+))\n{2,}/i"   => "<blockquote>$2</blockquote>\n",
        "/#+\s{1}(.+)\n+/i"             => "<h3>$1</h3>\n",
        "/\((.+?)\)\[(\S+?)\]/i"        => "<a href=\"$2\">$1</a>",
        "/\!\[(.+?)\]\((.+?)\)/i"       => "<img src=\"$1\" alt=\"$2\">",
        "/\n{2,}(-\s{1}(.+)\n{1}.+)/im" => "\n<ul>$1",
        "/(-\s{1}(.+)\n)\n+/im"         => "$1</ul>\n",
        "/\n?(-\s{1}(.+))\n?/i"         => "<li>$2</li>",
        "/^(.+)\n+/i"                   => "<p>$1</p>\n",
        "/\n+(.+)[\n+\Z]?/im"           => "<p>$1</p>\n",
    ];

    foreach ($patterns as $pattern => $replacement) {
        $string = preg_replace($pattern, $replacement, $string);
    }

    return $string;
}

// #############################################################################
// #############################################################################
// #############################################################################

function filter_date($date, $default = null) {
    static $re = '/^((?:19|20)\d\d)-?(0[1-9]|1[012])-?(0[1-9]|[12][0-9]|3[01])$/';
    $i = filter_var($date, FILTER_VALIDATE_REGEXP, ['options' => ['regexp' => $re]]);
    return (false === $i) ? $default : $i;
}

// #############################################################################
// #############################################################################
// #############################################################################

# Create a random 32 character MD5 token
function token() {
    return md5(str_shuffle(chr(mt_rand(32, 126)).uniqid().microtime(true)));
}

function random_str($length = 16) {
    $pool = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    return substr(str_shuffle(str_repeat($pool, 5)), 0, $length);
}

// #############################################################################
// #############################################################################
// #############################################################################

# Determine if a given string ends with a given value.
function str_ends_with($haystack, $needle) {
    return $needle == substr($haystack, strlen($haystack) - strlen($needle));
}

// #############################################################################
// #############################################################################
// #############################################################################

function strtol($str) {
    return is_long($str) ? $str : intval(preg_replace('/\D/', '', $str));
}

// #############################################################################
// #############################################################################
// #############################################################################

// buffer functions that may echo vs returning output,
// return echoed data if any, otherwise returned data.
function buffer(callable $callback) {
    ob_start();
    $result = call_user_func_array($callback, array_slice(func_get_args(), 1));
    $buffer = trim(ob_get_clean());
    return is_null($result) ? ('' === $buffer ? null : $buffer) : $result;
}

// #############################################################################
// #############################################################################
// #############################################################################

/**
 * RC4 symmetric cipher encryption/decryption
 * From <https://gist.github.com/farhadi/2185197>
 *
 * @license Public Domain
 * @param string key - secret key for encryption/decryption
 * @param string str - string to be encrypted/decrypted
 * @return string
 */
function rc4($str, $key) {
    $s = [];
    $res = '';

    for ($i = 0; $i < 256; $i++) {
        $s[$i] = $i;
    }

    for ($i = $j = 0; $i < 256; $i++) {
        $j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
        $x = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $x;
    }

    for ($i = $j = $y = 0; $y < strlen($str); $y++) {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $x = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $x;
        $res .= $str[$y] ^ chr($s[($s[$i] + $s[$j]) % 256]);
    }

    return $res;
}

// #############################################################################
// #############################################################################
// #############################################################################

# Get all of the given array except for a specified array of items.
function array_except(array $array, array $keys) {
    return array_diff_key($array, array_flip($keys));
}

# Get a subset of the items from the given array.
function array_only(array $array, array $keys) {
    return array_intersect_key($array, array_flip($keys));
}

// #############################################################################
// #############################################################################
// #############################################################################

function php_user_agent() {
    $fmt = 'Mozilla/5.0 (%s; %s %s) Zend/%s PHP/%s';
    return sprintf($fmt, PHP_SAPI, PHP_OS, php_uname('m'), zend_version(), PHP_VERSION);
}

// #############################################################################
// #############################################################################
// #############################################################################

function str_limit($value, $limit = 100, $end = '...') {
    return strlen($str) <= $limit ? $str : rtrim(substr($str, 0, $limit)).$end;
}

function str_truncate($str, $max = 256, $cap = '...') {
    return strtok(wordwrap(trim($str), $max, "$cap\n"), "\n");
}

// #############################################################################
// #############################################################################
// #############################################################################

function is_invokable($v) {
    return is_object($v) && method_exists($v, '__invoke');
}

// #############################################################################
// #############################################################################
// #############################################################################

function hashcash($email) {
    $count = 0;
    $hashcash = sprintf('1:20:%u:%s::%u', date('ymd'), $email, mt_rand());
    while (strncmp('00000', sha1($hashcash.$count), 5) !== 0) ++$count;
    return $hashcash.$count;
}

// #############################################################################
// #############################################################################
// #############################################################################

function join_paths() {
    return trim(join('/', array_map(function ($path) {
        return trim(str_replace('\\', '/', $path), '/');
    }, func_get_args())), '/');
}

// #############################################################################
// #############################################################################
// #############################################################################

function bin_to_ascii($bin) {
    return join(array_map(function ($i) {
        return ord(($i % 95) + 32);
    }, unpack('C*', $bin)));
}

function tx_pool($input, $pool) {
    $input_len = strlen($input);
    $pool_len = strlen($pool);
    for ($i = 0, $output = ''; $i < $input_len; $i++) {
        $output .= $pool[ord($input[$i]) % $pool_len];
    }
    return $output;
}

/*
$pool = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
$input = 'QjSH496pcT5CEbzjD/vtVeH03tfHKFy36d4J0Ltp3lRtee9HDxY3K';
print(tx_pool($pool, $input));
$chars_a = 'abcdef1234567890{}()<>[]';
$chars_b = 'i am the input!!';
$chars_c = bin_to_ascii(hash('md5', $chars_b, true));
echo tx_pool($chars_c, $chars_a);
*/

// #############################################################################
// #############################################################################
// #############################################################################

function format_bytes($bytes, $precision = 2) {
    $units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    # OR: # $bytes /= (1 << (10 * $pow));
    return round($bytes, $precision).' '.$units[$pow];
}

// #############################################################################
// #############################################################################
// #############################################################################

# Compares two strings in constant time whether they're equal or not.
if (!function_exists('hash_equals')) {
    function hash_equals($expected, $actual) {
        $expected = strval($expected).chr(0);
        $actual = strval($actual).chr(0);
        $result = ($elen = strlen($expected)) - ($alen = strlen($actual));

        for ($i = 0; $i < $alen; $i++) {
            $result |= (ord($expected[$i % $elen]) ^ ord($actual[$i]));
        }

        return 0 === $result;
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

# jmrware/LinkifyURL, Rev:20101010_1000, (c) 2010 Jeff Roberson - jmrware.com
function linkify($text) {
    $url_pattern = '/(\()((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\))
        |(\[)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\])
        |(\{)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\})
        |(<|&(?:lt|\#60|\#x3c);)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)
        (>|&(?:gt|\#62|\#x3e);)|((?: ^| [^=\s\'"\]]) \s*[\'"]?| [^=\s]\s+)
        ( \b(?:ht|f)tps?:\/\/[a-z0-9\-._~!$\'()*+,;=:\/?#[\]@%]+
        (?:(?!&(?:gt|\#0*62|\#x0*3e);| &(?:amp|apos|quot|\#0*3[49]|\#x0*2[27]);
        [.!&\',:?;]?(?:[^a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]|$)) &
        [a-z0-9\-._~!$\'()*+,;=:\/?#[\]@%]*)*[a-z0-9\-_~$()*+=\/#[\]@%])/imx';
    $url_replace = '$1$4$7$10$13<a href="$2$5$8$11$14">$2$5$8$11$14</a>$3$6$9$12';
    return preg_replace($url_pattern, $url_replace, $text);
}

function linkify_html($text) {
    $text = preg_replace('/&apos;/', '&#39;', $text);
    $section_html_pattern = '%([^<]+(?:(?!<a\b)<[^<]*)*|(?:(?!<a\b)<[^<]*)+)
        |(<a\b[^>]*>[^<]*(?:(?!</a\b)<[^<]*)*</a\s*>)%ix';
    return preg_replace_callback($section_html_pattern, function ($matches) {
        return isset($matches[2]) ? $matches[2] : linkify($matches[1]);
    }, $text);
}

// #############################################################################
// #############################################################################
// #############################################################################

# MicroTpl <http://github.com/unu/microtpl>
class MicroTpl {
    static function parse($tpl) {
        return preg_replace([
            '_{\@([^}]+)}_', # list array
            '_{\?([^}]+)}_', # show on true
            '_{\!([^}]+)}_', # show on false
            '_{\/([^}]+)}_', # closing mark
            '_{\&([^}]+)}_', # unescaped echo
            '_{([a-zA-Z0-9]+)}_', # escaped echo
            '_{([a-zA-Z0-9]+=[^}]+)}_', # assign variable
            '_{-?([^ }][^}]*)}_', # php code
        ], [
            '<?php $_sv_\1=get_defined_vars();foreach((isset($\1)&&is_array'.
                '($\1)?$\1:)as$_it_){ if(is_array($_it_))extract($_it_)?>',
            '<?php if(isset($\1)&&!!$\1){ ?>',
            '<?php if(!isset($\1)||!$\1){ ?>',
            '<?php }if(isset($_sv_\1)&&is_array($_sv_\1))extract($_sv_\1)?>',
            '<?= isset($\1)?$\1:""?>',
            '<?= isset($\1)?htmlspecialchars(\$\1,ENT_QUOTES):""?>',
            '<?php $this->\1?>',
            '<?php \1?>',
        ], $tpl);
    }
    function render($_tpl) {
        ob_start();
        extract((array) $this);
        eval('?>'.self::parse($_tpl));
        return ob_get_clean();
    }
    function renderFile($file) {
        return $this->render(file_get_contents($file));
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

# Minify and concat css files
function css_min($css_files) {
    ob_start(function ($output) {
        $output = preg_replace('/\/\*[^*]*\*+([^\/][^*]*\*+)*\//', '', $output);
        $output = preg_replace(['/[\r\n\t]/', '/\s+/'], ['', ' '], $output);
        return $output;
    });

    foreach ($css_files as $file) {
        include_once($file);
    }

    return ob_get_clean();
}

// #############################################################################
// #############################################################################
// #############################################################################

function value(&$var, $default = null) {
    if (!isset($var)) {
        return $default;
    } elseif (is_a($var, 'Exception')) {
        throw $var;
    } elseif (is_a($var, 'Closure')) {
        return $var();
    } elseif (is_object($var) && method_exists($var, '__invoke')) {
        return $var();
    } else {
        return $var;
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

function add_header_callback(callable $callback) {
    static $callbacks = [];

    $callbacks[] = $callback;

    header_register_callback(function () use (&$callbacks) {
        foreach ($callbacks as $callback) $callback();
    });
}

// #############################################################################
// #############################################################################
// #############################################################################

function add_include_path($path) {
    if (is_array($path) || is_object($path)) {
        foreach ($path as $p) {
            Flight::add_include_path($p);
        }
    } else {
        $incPath = get_include_path();
        $incPath = trim($incPath, PATH_SEPARATOR); // trim leading/trailing sep.
        $incPath = explode(PATH_SEPARATOR, $incPath); // Split on path sep.
        $incPath[] = $path; // Add $path to include path
        $incPath = array_map('trim', $incPath); // Trim all incl. path entries.
        $incPath = array_map('realpath', $incPath); // Returns false on failure.
        $incPath = array_filter($incPath); // Remove false entries
        $incPath = array_unique($incPath); // Remove duplicates
        $incPath = array_filter($incPath, 'is_dir'); // Retain only directories.
        $incPath = array_filter($incPath, 'is_readable'); // Only readable ones.
        $incPath = join(PATH_SEPARATOR, $incPath); // Recombine
        set_include_path($incPath);
    }
}

// #############################################################################
// #############################################################################
// #############################################################################

// #############################################################################
// #############################################################################
// #############################################################################

// #############################################################################
// #############################################################################
// #############################################################################

// #############################################################################
// #############################################################################
// #############################################################################

// #############################################################################
// #############################################################################
// #############################################################################
