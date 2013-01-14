<?php

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
