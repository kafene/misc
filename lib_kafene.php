<?php

# Hashcash is a computationally expensive operation for the sender, while being
# easily verified by the receiver. It proves this email was worth working for
# and isn't spam. From - http://github.com/Xeoncross/kit
function hashcash($email) {
    $count = 0;
    $hashcash = sprintf('1:20:%u:%s::%u', date('ymd'), $email, mt_rand());
    while(strncmp('00000', sha1($hashcashc.$count), 5) !== 0) { ++$count; }
    return $hashcash.$count;
}

# Event Handler
function event($name = null, $value = null) {
    static $events = [];
    # Name should be case insensitive.
    $name = strtolower(basename($name));
    # Get all - event();
    if(0 === func_num_args()) {
        return $events;
    }
    # Remove by name - event('myevent', false);
    elseif($name && false === $value) {
        unset($events[$name]);
    }
    # Remove all - event(false);
    elseif(empty($name) && null === $value) {
        $events = [];
    }
    # Attach event - event('myevent', $func);
    elseif(is_a($value, 'Closure')) {
        $events[$name][] = $value;
    }
    # Fire event - event('myevent'), event('myevent', ['arg1', 'arg2']);
    elseif($name && (is_array($value) || null === $value)) {
        if(!is_array($value)) {
            $value = [];
        }
        foreach(ifsetor($events[$name], []) as $fn) {
            if(is_array($result = call_user_func_array($fn, $value))) {
                $value = $result;
            }
        }
        return $value;
    }
}

# Find files recursively in a given directory
# Filtered by a regular expression pattern
function rscandir($dir, $filter_pattern = '/.*/') {
    if(!is_dir($dir)) { return []; }
    $df = \FilesystemIterator::KEY_AS_PATHNAME
        | \FilesystemIterator::CURRENT_AS_FILEINFO
        | \FilesystemIterator::SKIP_DOTS
        | \FilesystemIterator::UNIX_PATHS;
    # | \FilesystemIterator::FOLLOW_SYMLINKS;
    $rf = \RecursiveIteratorIterator::SELF_FIRST
        | \RecursiveIteratorIterator::CATCH_GET_CHILD;
    $rd = new \RecursiveDirectoryIterator($dir, $df);
    $it = new \RecursiveIteratorIterator($rd, $rf);
    $rx = new \RegexIterator($it, $filter_pattern);
    $found = iterator_to_array($rx);
    $files = array_filter(array_keys($found), 'is_file');
    $files = array_intersect_key($found, array_flip($files));
    return $files;
}

# Recursively remove a directory
function remove_dir($path) {
    if(is_link($path)) {
        return unlink($path);
    }
    foreach(new \RecursiveDirectoryIterator($path) as $file) {
        if(in_array($f->getFilename(), ['.', '..'])) {
            continue;
        }
        if($file->isLink()) {
            unlink($file->getPathName());
            continue;
        }
        if($file->isFile()) {
            unlink($file->getRealPath());
            continue;
        }
        if($file->isDir()) {
            remove_dir($file->getRealPath());
        }
    }
    return rmdir($path);
}

# Get the UNIX file permissions for a file, e.g. 0644, 0755
function file_permissions($file) {
    return substr(sprintf('%o', fileperms($file)), -4);
}

# PHP lacks a str_putcsv function despite having str_getcsv
# and fgetcsv/fputcsv. This uses an in-memory file handle and
# fputcsv to simulate str_putcsv.
if(!function_exists('str_putcsv')) {
    function str_putcsv($input, $delimiter = ',', $enclosure = '"') {
        $fh = fopen('php://temp', 'r+');
        fputcsv($fh, $input, $delimiter, $enclosure);
        rewind($fh); # fseek($fp, 0);
        $data = fread($fh, 1048576);
        fclose($fh);
        return rtrim($data, "\n");
    }
}

