<?php function mi($Y,$T){$G=[];$H=0;foreach(glob("$Y*.md")as$I){$J=file($I);$K=
strtotime($J[1]);$G[$K.$H++]=[$J[0],$K,basename($I)];}krsort($G);if(!is_file($D
=$Y.(@$_GET['f']?:0)))foreach(@$G as$Z)@$E.="\n- [$Z[0]](?f=$Z[2])  \n".date(
'Y-m-d',$Z[1]);die("<xmp theme=cerulean><div style='width:60%;margin:0 auto'>
<h1><a href=?>$T</a></h1>\n".(@$E?:'# '.@file_get_contents($D))."</xmp><title>
$T</title><script src=//strapdownjs.com/v/0.1/strapdown.js></script>");}
# mi('p/','My Blog');

#
# mi
#
# Possibly the world's smallest blog.
# Make a folder called "p", or whatever you send to $Y (first argument)
# The blog site title is $T (second argument)
# Place posts with file extension of .md in it
# First line of each post is the Title
# Second line is the date formatted YYYY-MM-DD
# Third line, leave blank
# The rest of the file is the contents of the post.
# The front page will list posts sorted by date, newest first.
# Clicking a post title goes to the post.
# That's it.
# Example, using folder "posts":
# ----> mi('posts/', "Bob's Articles");
# Themes available at strapdownjs.com
# By the way, don't actually use this. It is just an experiment.
#
