<?php

# stackoverflow.com/questions/2510434
function size_format($sz, $fmt='%-7.2f %s', $ex=array('B','K','M','G','T')) {
  $p = (int)min(floor(log($b=max($sz,0)?:0)/log(1024)),count($ex)-1);
  return sprintf($fmt, round($b/=pow(1024,$p),2), $ex[$p].($p>0?'iB':''));
}

# Like a recursive glob(). can match for a file regex pattern.
function glob_recursive($path = '.', $regex = '/^.*$/i') {
  $path = realpath($path); $out = [];
  foreach(new \RegexIterator(
    new \RecursiveIteratorIterator(
      new \RecursiveDirectoryIterator($path
        , \FilesystemIterator::KEY_AS_PATHNAME
        | \FilesystemIterator::CURRENT_AS_FILEINFO
        | \FilesystemIterator::SKIP_DOTS
      ), \RecursiveIteratorIterator::SELF_FIRST
    ), $regex, \RecursiveRegexIterator::GET_MATCH
  ) as $v) $out[] = $v[0];
  return $out;
}

# Verify format of, or generate a UUID
function uuid($uuid = null) {
  if($uuid !== null) {
    $v   = '[0-9a-f]';
    $pat = "/^\{?$v{8}-?$v{4}-?$v{4}-?$v{4}-?$v{12}\}?$/i";
    return 1 === preg_match($pat, $uuid);
  }
  return sprintf(
    '%04x%04x-%04x-%04x-%04x-%04x%04x%04x'
  , mt_rand(0,0xffff), mt_rand(0,0xffff)
  , mt_rand(0,0xffff), mt_rand(0,0x0fff) | 0x4000
  , mt_rand(0,0x3fff) | 0x8000, mt_rand(0,0xffff)
  , mt_rand(0,0xffff), mt_rand(0,0xffff));
}

function is_ascii($str) {
  return !preg_match('/[^\x00-\x7F]/S', $str);
}

function random_str($len, $include_symbols = true) {
  $out = ''; $pool = $include_symbols ? range('!','~')
  : array_merge(range('A','Z'), range('a','z'), range('0','9'));
  for($i=0; $i<$len; $i++) $out .= $pool[mt_rand(0,count($pool)-1)];
  return $out;
}

/**
 * SOURCE: http://www.user-agents.org/
 * @param bool $deny_no_ua - reject visitors without a UA header
 * @param bool $silent - Send a 404 not found instead of 403 forbidden.
 */
function banbots($deny_no_ua = true, $silent = true, $extra = '') {
  $b='spider|arach|bot|seek|robo|crawl|snoop|search|cach|archiv|slurp|'
     'bing|yaho|amzn|a9|harves|curl|aria2|axel|wget|teoma|libww|urlli|'
     'leech|aol|altav|weasel|prox|lycos|llect|backd|loade|dmoz|docomo|'
     'twitt|faceboo|daemon|clust|topix|miner|scan|baidu|tineye|google|'
     'java|httpcl|httpun|nutch|webmon|monit|httrack|convera|grub|tron|'
     'speedy|bibnum|findlink|scient|ioi|agent|yanga|yandex|yager|yeti|'
     'postrank|xget|patrol|turnitin|page2rss|scribd|linkdex|zdex|ezoo|'
     'mail\.ru|trix|findthat|ndex|summ|finder|count|sogou|wotbox|duck|'
     'ichiro|rocke|drupact|gnam|coccoc|privox|accel|checko|checke|ack|'
     'bookm|munch|rss|regat|anony|izer|blekko|runne|rules|allthe|cuil|'
     'giga|alexa|mirro|yzer|askj|backrub|phant|juice|gett|guzz|funnel|'
     'gazz|rover|creep|verif|getur|golem|grapn|experi|gulp|gobb|infor|'
     'decont|specto|stat|walke|lockon|worm|marvin|mediaf|meshex|moget|'
     'munin|motor|monster|muscat|shincha|chacha|zoek|webmap|mech|scoo|'
     'forag|nomad|zexpl|occam|octo|gathe|pack|parasi|pegas|sift|valet|'
     'tkww|void|bandit|catch|nator|reape|blayer|fetch|snarf|watch|wwc|'
     'dynami|bwalk|bvac|zinge|evil|loder|loade|viru|dexer|pubsub|tomz|'
     'launche|checkl|coral|dbrows|dead|deep|dig|dnsr|ebrows|thcom|eju|'
     'siph|endo|extrac|demon|downl|relic|favor|scoot|sitebar|snag|suk|'
     'suck|recon|winder|squid|viewe|xenu|sleut|yoofind'.$extra;
  $kill = function() use($silent) {
    die(header(getenv('SERVER_PROTOCOL') ?: 'HTTP/1.0'
     . ($silent ? ' 404 Not Found' : ' 403 Forbidden'), true
     ,  $silent ? 404 : 403));
  };
  if(getenv('HTTP_USER_AGENT')) {
    $ua = getenv('HTTP_USER_AGENT');
  } else { if($deny_no_ua) $kill(); }
  if(preg_match('/'.$b.'/i', $ua)) $kill();
}

function strips($a) {
	if(is_array($a))
		foreach($a as $k => $v)
			$v[$k] = strip($v);
	else $v = stripslashes($v);
	return $v;
}
