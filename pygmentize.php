<?php

function pygmentize($lang, $code, $ep = 'http://pygments.appspot.com/') {
  $url = 'https://kafene.github.com/asset/misc/pygments.css';
  $css = '<style>.linenos{background-color:#f0f0f0;padding-right:10px}
  .lineno{background-color:#f0f0f0;padding:0 5px 0 5px} .nd,.ow{color:#a2f}
  .na{color:#7D9029} .hll{background-color:#ffffcc} .ne{color:#D2413A}
  .w{color:#bbb} .err{border:1px solid #FF0000} .nc,.nf,.nn{color:#00f}
  .c,.c1,.cs,.cm,.ge,.sd{font-style:italic} .no{color:#800} .ni{color:#999}
  .vg,.vi,.vc,.ss,.nv{color:#19469D} .c,.cm,.c1,.cs{color:#408080}
  .gh,.gp,.gu,.kd,.kn,.kr,.nc,.ni,.ne,.nn,.nt,.ow,.se,.si{font-weight:bold}
  .k,.kc,.kd,.kn,.kp,.kr,.nb,.nt,.sx,.bp{color:#954121} .nl{color:#A0A000}
  .mo,.mi,.mf,.mh,.il,.o,.m{color:#666666} .sr,.si{color:#b68}
  .cp{color:#BC7A00} .gd{color:#A00000} .gr{color:#f00} .gh,.gp{color:#000080}
  .gi{color:#00A000} .go{color:#808080} .gu{color:#800080} .gt{color:#0040D0}
  .s,.s2,.sd,.sb,.sc,.sh,.s1{color:#219161} .kt{color:#B00040} .se{color:#b62}
  td.docs .docparam{color:#DB251A;font-weight:bold}</style>';
  $post = 'lang='.urlencode($lang).'&code='.urlencode($code);
  $ch = curl_init();
  curl_setopt_array($ch, array(
    \CURLOPT_URL => $ep
  , \CURLOPT_POST => 2
  , \CURLOPT_RETURNTRANSFER => 1
  , \CURLOPT_POSTFIELDS => $post
  ));
  $res = curl_exec($ch); curl_close($ch);
  return array('html' => $res, 'css' => $css);
}
