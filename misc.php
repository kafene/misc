<?php

# stackoverflow.com/questions/2510434
function size_format($sz, $fmt='%-7.2f %s', $ex=array('B','K','M','G','T')) {
  $p = (int)min(floor(log($b=max($sz,0)?:0)/log(1024)),count($ex)-1);
  return sprintf($fmt, round($b/=pow(1024,$p),2), $ex[$p].($p>0?'iB':''));
}
