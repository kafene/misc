<?php

/**
 * @package - linkify. File: linkify.php, Version 20101010_1000
 * @copyright - Copyright (c) 2010 Jeff Roberson - http://jmrware.com
 * @license - MIT License: http://www.opensource.org/licenses/mit-license.php
 * @description - This script linkifys http URLs on a page.
 */
static function linkify($text) {
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
