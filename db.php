<?php

namespace kafene;

class DB {
    static $instances = [];

    static function get($filename = ':memory:', $name = 'default') {
        if(isset(static::$instances[$name])) {
            return static::$instances[$name];
        }
        static::$instances[$name] = new \PDO("sqlite:$filename", '', '', [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            # \PDO::ATTR_EMULATE_PREPARES => false,
            # \PDO::ATTR_STRINGIFY_FETCHES   => false,
            # \PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8',
            # \PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,
            # \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            # \PDO::ATTR_CASE => \PDO::CASE_LOWER,
        ]);
        static::$instances[$name]->exec('PRAGMA foreign_keys = ON');
    }

    static function getInstance($name) {
        if(isset(static::$instances[$name])) {
            return static::$instances[$name];
        }
    }

    static function e($sql, $name = 'default') {
        if($link = static::getInstance($name)) {
            return $link->quote($sql);
        }
    }

    static function showTables(\PDO $link) {
        $sql = "
            SELECT name FROM sqlite_master
                WHERE type IN ('table', 'view')
                AND name NOT LIKE 'sqlite_%'
            UNION ALL
            SELECT name FROM sqlite_temp_master
                WHERE type IN ('table', 'view')
            ORDER BY 1
        ";
        return $link->query($sql)->fetchAll($link::FETCH_ASSOC);
    }

    static function epochColumn($name = 'time') {
        return " $name TIMESTAMP DEFAULT (strftime('%s', 'now')) ";
    }
}
