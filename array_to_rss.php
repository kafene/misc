<?php

/*
$options = array(
  'base_url' => ''
, 'title'    => ''
, 'link_fmt' => ''
, 'time_id'  => ''
, 'title_id' => ''
, 'link_id'  => ''
)
*/

function array_to_rss(
  array $items
, $options = array(
    'base_url' => 'http://localhost/'
  , 'title'    => 'Blog'
  , 'link_fmt' => 'http://localhost/index.php?id={{id}}&from=rss'
  , 'time_id'  => 'time'
  , 'title_id' => 'title'
  , 'link_id'  => 'id'
  )
){
  extract($options);
  if(!isset($base_url) || empty($base_url)) {
     $p = parse_url($link_fmt);
     $base_url = sprintf('%s://%s/%s', $p['scheme'], $p['host'], $p['path']);
  }
  $o = '<?xml version="1.0" encoding="UTF-8"?>'."\n"
     . '<rss version="2.0">'."\n"
     . "<channel>\n"
     . "<title>$title</title>\n"
     . "<description>$title -- RSS Feed</description>\n";
  foreach($items as $i) {
    $time = is_int($i[$time_id])
      ? $i[$time_id]
      : (strtotime($i[$time_id]) ?: $i[$time_id]);
    $o .= "<item>\n"
        . "<title>{$i[$title_id]}</title>\n"
        . "<link>$base_url</link>\n"
        . "<pubDate>".date(\DATE_RSS, $time)."</pubDate>\n"
        . "<guid>".str_ireplace('{{id}}',$i[$link_id],$link_fmt)."</guid>\n"
        . "</item>";
  }
  return "$o\n</channel>\n</rss>";
}
