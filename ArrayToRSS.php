<?php

function array_to_rss(
  array $items
, $url = 'http://localhost/'
, $title = 'Blog'
, $link_id = 'id'
, $time_id = 'time'
, $title_id = 'title'
, $body_id = 'body'
, $link_fmt = 'http://localhost/site.php?id={{id}}&from=rss'
){
  $out = '<?xml version="1.0" encoding="UTF-8"?>'
       . '<rss version="2.0"><channel>'
       . "<title>$title</title>"
       . "<description>$title - RSS Feed</description>";
  foreach($items as $item) {
    $link = str_ireplace('{{id}}', $item[$link_id], $link_fmt);
    $out .= '<item>'
          . "<title>{$item[$title_id]}</title>"
          . "<link>$link</link>"
          . '<pubDate>'
          . date(\DATE_RSS
          , is_int($item[$time_id])
            ? $item[$time_id]
            : (strtotime($item[$time_id])
            ?: $item[$time_id]))
          . '</pubDate>'
          . '<guid isPermaLink="false">'.$link.'</guid>'
          . (isset($item[$body_id])
          ? "<description><![CDATA[\n"
          . str_replace(']', '&#93;', $item[$body_id])."\n"
          . '<p><b><a href="'.$link.'">#</a></b></p>'
          . "\n]]></description>"
          : '')
          . '</item>';
  }
  return $out.'</channel></rss>';
}
