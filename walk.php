<?php

# This is like array_walk_recursive, but it doesn't require using references,
# and it can iterate over anything Traversable, not just arrays,
# so for this reason it is not called "array_map_recursive"
function rmap($it, callable $fn) {
    foreach ($it as $i => &$v) {
        $v = is_array($v) || is_object($v) ? rmap($v, $fn) : $fn($v, $i);
    }
    return $it;
}

$testArray = [
    'users' => ['bob', 'jen', 'sam'],
    'people' => [
        ['name' => 'bob', 'age' => 33, 'gender' => 'm'],
        ['name' => 'jen', 'age' => 20, 'gender' => 'f'],
        ['name' => 'sam', 'age' => 19, 'gender' => 'm'],
    ],
    'cars' => [
        'honda' => ['owners' => ['jen']],
        'buick' => ['owners' => ['bob', 'sam']],
    ],
];

var_dump(rmap($testArray, function ($value) {
    return strtoupper($value);
}));
