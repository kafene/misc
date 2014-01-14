<?php

# Array utilities
# Some of these functions are from Laravel <https://github.com/laravel>
class ArrayUtil
{
    # Regular expression array key search
    static function from(array $arr, $key, $default = null, $one = true) {
        if (array_key_exists($key, $array)) {
            return $array[$key];
        }

        $grep = preg_grep('/^('.preg_quote($key, '/').')$/i', array_keys($array));
        $ret = array_intersect_key($arr, array_flip($grep));

        return empty($ret) ? $default : ($one ? end($ret) : $ret);
    }

    static function grepKeys($pattern, array $input, $flags = 0) {
        $keys = preg_grep($pattern, array_keys($input), $flags);
        $vals = [];

        foreach ($keys as $k) {
            $vals[$k] = $input[$k];
        }

        return $vals;
    }

    # Check if $array keys are exactly the same as $need
    static function keysEqual(array $array, array $need, $strict = true) {
        $have = array_keys($array);
        ksort($need);
        ksort($have);
        return $strict ? ($need === $have) : ($need == $have);
    }

    # Check if all of the keys from $keys are in the keys of $array
    static function keysExist(array $array, array $keys) {
        $keys = array_flip($keys);
        $diff = array_diff_key($keys, $array);
        return empty($diff);
    }

    # Convert XML to an array
    static function xmlToArray($xml) {
        return json_decode(json_encode(simplexml_load_string($xml)), true);
    }

    # Get all of items from $a that don't have keys in $keys
    static function except(array $array, $keys) {
        return array_diff_key($array, array_flip((array) $keys));
    }

    # Get a only items from the array with keys specified in $keys
    static function only(array $array, $keys) {
        return array_intersect_key($array, array_flip((array) $keys));
    }

    static function transpose(array $array) {
        array_unshift($array, null);
        return call_user_func_array('array_map', $array);
    }

    # Get the first element of an array.
    static function head(array $array) {
        return reset($array);
    }

    # Get the last element from an array.
    static function last(array $array) {
        return end($array);
    }

    # Sort the array using the given sort-constant or callback.
    static function sort(array $array, $method = SORT_REGULAR) {
        if (is_int($method)) {
            asort($array, $method);
        } else {
            uasort($array, $method);
        }

        return $array;
    }

    # Get a value from the array, and remove it.
    static function pull(array &$array, $key) {
        $value = static::get($array, $key);
        static::remove($array, $key);
        return $value;
    }

    # Pluck an array of values from an array.
    static function pluck(array $array, $value, $key = null) {
        $ret = [];

        foreach ($array as $item) {
            $itemValue = is_object($item) ? $item->{$value} : $item[$value];

            if (null === $key) {
                $ret[] = $itemValue;
            } else {
                $itemKey = is_object($item) ? $item->{$key} : $item[$key];
                $ret[$itemKey] = $itemValue;
            }
        }

        return $ret;
    }

    # Set an array item to a given value using "dot" notation.
    static function set(array &$array, $key, $value) {
        if (null === $key) {
            return $array = $value;
        }

        $keys = explode('.', $key);

        while (sizeof($keys) > 1) {
            $key = array_shift($keys);

            if (!isset($array[$key]) || !is_array($array[$key])) {
                $array[$key] = array();
            }

            $array =& $array[$key];
        }

        $array[array_shift($keys)] = $value;

        return $array;
    }

    # Get an item from an array using "dot" notation.
    static function get(array $array, $key, $default = null) {
        if (null === $key) {
            return $array;
        }

        if (isset($array[$key])) {
            return $array[$key];
        }

        foreach (explode('.', $key) as $part) {
            if (!is_array($array) || !array_key_exists($part, $array)) {
                return $default;
            }

            $array = $array[$part];
        }

        return $array;
    }

    # Remove an array item from a given array using "dot" notation.
    static function remove(&$array, $key) {
        $keys = explode('.', $key);

        while (sizeof($keys) > 1) {
            $key = array_shift($keys);

            if (!isset($array[$key]) || !is_array($array[$key])) {
                return;
            }

            $array =& $array[$key];
        }

        unset($array[array_shift($keys)]);
    }

    # Fetch a flattened array of a nested array element.
    static function fetch($array, $key) {
        foreach (explode('.', $key) as $part) {
            $ret = [];

            foreach ($array as $value) {
                $value = (array) $value;
                $ret[] = $value[$part];
            }

            $array = array_values($ret);
        }

        return array_values($ret);
    }

    # Flatten a multi-dimensional array into a single level.
    static function flatten(array $array) {
        $ret = [];

        array_walk_recursive($array, function ($i) use (&$ret) {
            $ret[] = $i;
        });

        return $ret;
    }

    # Return the first element in an array passing a given truth test.
    static function first(array $array, callable $callback, $default = null) {
        foreach ($array as $key => $value) {
            if ($callback($key, $value)) {
                return $value;
            }
        }

        return $default;
    }

    # Build a new array using a callback.
    static function build(array $array, callable $callback) {
        $ret = [];

        foreach ($array as $key => $value) {
            list($innerKey, $innerValue) = $callback($key, $value);
            $ret[$innerKey] = $innerValue;
        }

        return $ret;
    }

    # Divide an array into two arrays. One with keys and the other with values.
    static function divide(array $array) {
        return [array_keys($array), array_values($array)];
    }

    # Add an element to an array if it doesn't exist.
    static function add(array $array, $key, $value) {
        if (!array_key_exists($key, $array)) {
            $array[$key] = $value;
        }

        return $array;
    }

    # Flatten a multi-dimensional associative array with dots.
    static function dot(array $array) {
        $ret = [];

        foreach ($array as $key => $value) {
            if (is_array($value)) {
                $ret = array_merge($ret, static::dot($value, $key.'.'));
            } else {
                $ret[$key] = $value;
            }
        }

        return $ret;
    }

    # Replace a given value in the string sequentially with an array.
    static function strReplace($search, array $replace, $subject) {
        foreach ($replace as $value) {
            $subject = preg_replace("/$search/", $value, $subject, 1);
        }

        return $subject;
    }

    # Replace a given pattern with each value in the array in sequentially.
    static function gsub($pattern, &$replacements, $subject) {
        return preg_replace_callback($pattern, function ($m) use (&$replacements) {
            return array_shift($replacements);
        }, $subject);
    }
}
