<?php namespace kafene;

/*

# file index

* works for subdirectories and navigation, not just a single directory!
* It could probably be less confusing but it works. for me at least.
* It's probably not safe for a public site, its just for dev environment.

* usage is just: `echo \kafene\index($_GET);`

*/
function index($input = array(), $wrap_html = true) {
  if(empty($input))
    $input = $_GET;
  // get current base directory
  $base = isset($input['base'])
    ? strtr($input['base'], '\\', '/')
    : '.';
  // find directories in this directory
  $dirs = glob($base.'/*', GLOB_ONLYDIR);
  // Find files in this directory
  $files = array_diff(glob($base.'/*'), $dirs);
  // get length of directory name
  $baselen = strlen($base);
  // get previous directory from current base (prev = ..)
  $prev = explode('/', './'.ltrim($base, './'));
  if(count($prev)) array_pop($prev);
  $prev = implode('/', $prev);
  // If the base was empty prev should be too
  if(!$base || $base == '.') $prev = '';
  // Link to the base
  $basl = '?base='.$base;
  // Now transform base to empty or add trailing slash 
  $base = $base == '.' ? '' : $base.'/';
  // get sort method from input
  $sm = isset($input['sort']) ? (string)$input['sort'] : 0;
  // get files found
  $ff = array();
  foreach($files as $file)
    $ff[] = array(
      'name'=> ($name = ltrim(substr($file, $baselen), '/'))
    , 'type'=>substr($name, strrpos($name, '.') + 1)
    , 'mod'=>filemtime($file)
    , 'size'=>filesize($file)
    );
  // define a function to sort items by column (name,type,size,mod)
  $sort = function($items, $col) {
    if(!$col) return $items;
    $temp = $out = array();
    foreach($items as $key => $val)
      $temp[$key] = strtolower($val[$col]);
    asort($temp);
    foreach($temp as $key => $val)
      $out[] = $items[$key];
    return $out;
  };
  // define a function to get the file size in human-readable form
  $format = function($size) {
    /* http://stackoverflow.com/questions/2510434 */
    $ext = array('B', 'KiB', 'MiB', 'GiB', 'TiB');
    $pow = min(
      floor(\log($bytes = max($size, 0) ?: 0) / \log(1024))
    , count($ext) - 1
    );
    $bytes = round($bytes /= pow(1024, $pow), 2);
    return sprintf('%-7.2f %s', $bytes, $ext[$pow]);
  };
  // get self filename
  $me = basename(getenv('SCRIPT_FILENAME'));
  // If we're wrapping html (to use as an index file) get the html ready
  $out = !$wrap_html ? '' : '<!doctype html>
  <html><head><meta charset="utf-8">
  <title>'.($base ? $base.' - ' : ' / - ').' - Directory Index</title>
  <style>
    html { font-family:"Segoe UI", "Droid Sans", sans-serif; }
    body { margin:2% auto; width:85%; }
    pre, code { font-size:100%; }
    a { text-decoration:none; }
    a, h1 a:visited, .header a:visited { color:#11a; display:inline; }
    a:hover { text-decoration:underline; color:#006; }
    a:visited { color:purple; }
    h1 { padding:0.5em 0; margin:0; font-size:110%; }
    table { width:100%; border-collapse:collapse; }
    th { text-align:left; padding:0.5em 0; }
    td { padding:0.2em 0.5em; border:1px solid #eee; }
    tr:not(.header):hover { background:#eee; }
    table.files td { width:33%; white-space:nowrap; }
  </style>
  </head><body class="directoryindex">';
  $out .= '
    <table class="dirs">
    <tr class="header"><th>
      <h1><a href="'.$me.'">Document Root</a></h1>
    </th></tr>
    <tr class="header"><th><b>Directories</b>:</th></tr>';
  // If there is a previous directory then link to it as ..
  if($prev) {
    $out .= '<tr><td><a href="'.$me.'?base='.$prev.'">..</a></td></tr>';
  }
  foreach($dirs as $dir) {
    $out .= '<tr><td><a href="'.$me.'?base='.$base
    . ($dir = trim(substr($dir, strlen($base)), './')) // format dir name
    . '">'.$dir.'</a></td></tr>';
  }
  /* Add the header table with sort method links */
  $out .= '</table><table class="files">
    <tr class="header sort">
    <th><a href="'.$me.$basl.'&sort='.($sm == 'name' ? 'r' : '').'name">Filename:</a></th>
    <th><a href="'.$me.$basl.'&sort='.($sm == 'type' ? 'r' : '').'type">Type:</th>
    <th><a href="'.$me.$basl.'&sort='.($sm == 'mod' ? 'r':'').'mod">Modified:</th>
    <th><a href="'.$me.$basl.'&sort='.($sm == 'size' ? 'r':'').'size">Size:</th>
    </tr>';
  // Sort and display the files found by the sort method
  foreach(($sm[0] == 'r'
    ? array_reverse($sort($ff, substr($sm, 1)))
    : $sort($ff, $sm)) as $file)
  {
    $out .= '<tr>
    <td><a href="'.$base.$file['name'].'">'.$file['name'].'</a></td>
    <td>'.strtoupper($file['type']).'</td><td>'.date('r',$file['mod']).'</td>
    <td><code>'.$format($file['size']).'</code></td>
    </tr>';
  }
  return $out.'</table>'
    . ($wrap_html ? '</body></html>' : '');
}
