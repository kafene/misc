<?php #(C) kafene.org 2012 /Post@($Y='p/')*.md,line1=title,2=date,3='',4+=txt/md
function mi($Y){$A=$_SERVER;$C=$A['HTTP_HOST'];$B='//'.$C.$A['SCRIPT_NAME'];$D=
$Y.(@$_GET['f']?:0);$G=[];$H=0;foreach(glob("$Y*.md")?:[]as$I){$J=file($I);$K=
strtotime($J[1]);$G[$K.$H++]=[$J[0],$K,basename($I)];}@krsort($G);if(!is_file(
$D))foreach($G as$Z)@$E.="\n- [{$Z[0]}]($B?f={$Z[2]})  \n".date('Y-m-d',$Z[1]);
die("<xmp theme=cerulean><div style='width:60%;margin:0 auto'><h1><a href=$B>$C
</a></h1>\n".(@$E?:'# '.@file_get_contents($D))."</xmp><title>$C</title><script
src=//strapdownjs.com/v/0.1/strapdown.js></script>");}#mi('p/');

// its code golf. its a blog. kinda.