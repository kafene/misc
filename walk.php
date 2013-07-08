<?php

# This is something like array_map, except recursive, and with additional arguments.
# Only used it once but I found it useful for whatever purpose it had, so... here.
function walk(callable $func, array $array, array $args = []) {
    $parent = __NAMESPACE__ .'\\'. __FUNCTION__;
    return array_map(function($v) use ($func, $args, $parent) {
        return is_array($v)
            ? $parent($func, $v, $args)
            : call_user_func_array($func, array_merge([0 => $v], $args));
    }, $array);
}

$testArray = [
    'bob',
    'users' => ['bob', 'jill', 'sam'],
    'people' => [
        ['name' => 'bob', 'age' => 33, 'gender' => 'male'],
        ['name' => 'jill','age' => 20, 'gender' => 'female'],
        ['name' => 'sam', 'age' => 19, 'gender' => 'male']
    ],
    'cars' => [
        'honda' => [
            'owners' => ['jill'],
        ],
        'toyota' => [
            'owners' => ['bob', 'sam'],
        ],
    ],
];
print '<PRE>';
var_dump(walk('strtoupper', $testArray));

