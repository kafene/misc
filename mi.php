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
# Place posts with file extension of .md in it formatted as follows:
# - First line of each post is the Title
# - Second line is the date formatted YYYY-MM-DD
# - Third line, leave blank
# - The rest of the file is the contents of the post.
# The blog site title is $T (second argument)
# The front page will list posts sorted by date, newest first.
# Clicking a post title goes to the post.
# That's it.
# Example, using folder "posts":
# ----> mi('posts/', "Bob's Articles");
# Themes available at strapdownjs.com
# By the way, don't actually use this. It is just an experiment.
#

# Here is the source code commented and more meaningful,
# so you can see how it works:

function mi_unminified($path = 'p/', $site_title = 'My Blog') {
    $entries = []; # Array of entries.
    $count = 0; # Count of entries.
    # Get all .md files in the specified path.
    # I realize it is inefficient to do this on every request, as the result
    # will be unused if there is a get param leading to a valid entry, but
    # I did it this way for the sake of compacting the source, not to be
    # smart about performance!
    foreach(glob("$path*.md") as $file) {
        $entry = file($file); # Read the file into an array of lines.
        $time = strtotime($entry[1]); # Second line.
        $key = $time.$count++; # A unique key, but sortable by date/time.
        $entries[$key] = [
            $entry[0], # The title.
            $time,
            basename($I) # The filename.
        ];
    }
    krsort($entries); # Sort so that the newest is on top.
    # If the user is using the get param 'f', look for that inside the path.
    # This makes for some ugly urls - mi.php?f=my_blog_entry_1.md ... oh well.
    # Otherwise look for a file named '0' (so make sure it doesn't exist!)
    $requested_entry = $path.(isset($_GET['f']) ? $_GET['f'] : 0);
    $entry_list = ''; # Set this up so to avoid a notice without @.
    # If there is no such entry then we create the index listing:
    if(!is_file($requested_entry) {
        foreach($entries as $entry) {
            $title = $entry[0];
            $filename = $entry[2];
            # Construct a markdown link to the file as part of a list. Note the
            # 2 trailing spaces so the next line is part of the same list item.
            $entry_list .= "\n- [".$title."](?f=".$filename.")  \n";
            # Format the entry time on the next line:
            $entry_list .= date('Y-m-d', $entry[1]);
        }
    }
    # If we had an entry to print (meaning the listing generation was skipped),
    # use that, with the contents prepended with '#' so as to make a markdown
    # <H1> tag for the title. Otherwise show the listing.
    if (empty($entry_list) && is_readable($requested_entry)) {
        $output = '# '.file_get_contents($requested_entry);
    } else {
        $output = $entry_list;
    }
    # In here, the XMP tag is part of the way strapdownjs works
    # Omitting the closing DIV tag somehow allowed it to look much
    # nicer, so I did.
    # Strapdownjs will handle rendering it into a nice looking page
    # and pulls in CSS and javascript to perform markdown transformation.
    # If it ever goes down, this won't work anymore...
    print "<xmp theme=cerulean>".
        "<div style='width:60%;margin:0 auto'>".
        "<h1><a href=?>$site_title</a></h1>\n".
        $output.
        "</xmp>".
        "<title>$site_title</title>". # Odd place for a title tag, but it works.
        "<script src='//strapdownjs.com/v/0.1/strapdown.js'></script>";
    # A bit nicer than die(), but an extra character..
    exit;
}
