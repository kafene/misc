<?php

/* from: https://github.com/Xeoncross/kit . http/mail header- X-Hashcash: */
function _hashcash($email) {
  $i = 0;
  $hashcash = sprintf('1:20:%u:%s::%u', date('ymd'), $email, mt_rand());
  while(strncmp('00000', sha1($hashcash.$i), 5) !== 0) ++$i;
  return $hashcash.$i;
}

/* @ linkify, v 20101010_1000, @copyright 2010 Jeff Roberson <jmrware.com>
 * @license - MIT: http://www.opensource.org/licenses/mit-license.php */
function linkify($text) {
  $patt = '/(\()((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\))
  |(\[)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\])
  |(\{)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)(\})
  |(<|&(?:lt|\#60|\#x3c);)((?:ht|f)tps?:\/\/[a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]+)
  (>|&(?:gt|\#62|\#x3e);)|((?: ^| [^=\s\'"\]]) \s*[\'"]?| [^=\s]\s+)
  ( \b(?:ht|f)tps?:\/\/[a-z0-9\-._~!$\'()*+,;=:\/?#[\]@%]+(?:
  (?!&(?:gt|\#0*62|\#x0*3e);| &(?:amp|apos|quot|\#0*3[49]|\#x0*2[27]);
  [.!&\',:?;]?(?:[^a-z0-9\-._~!$&\'()*+,;=:\/?#[\]@%]|$)) &
  [a-z0-9\-._~!$\'()*+,;=:\/?#[\]@%]*)*[a-z0-9\-_~$()*+=\/#[\]@%])/imx';
  $replace = '$1$4$7$10$13<a href="$2$5$8$11$14">$2$5$8$11$14</a>$3$6$9$12';
  return preg_replace($patt, $replace, $text);
}
static function linkify_html($text) {
  $text = preg_replace('/&apos;/', '&#39;', $text);
  $patt = '%([^<]+(?:(?!<a\b)<[^<]*)*|(?:(?!<a\b)<[^<]*)+)
  | (<a\b[^>]*>[^<]*(?:(?!</a\b)<[^<]*)*</a\s*>)%ix';
  return preg_replace_callback($patt, function($m){
    return (isset($m[2])) ? $m[2] : linkify($m[1]);
  }, $text);
}



