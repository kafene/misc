<?php

namespace kafene;

// ---
// Stupid DB Helper
// ---
class DB
{
    protected static $instances = [];
    protected $log = 'php://stdout';
    protected $pdo;
    protected $id;

    /** @constructor */
    public function __construct($pdo, $log = null, $id = null)
    {
        $this->pdo = $pdo;
        $this->log = $log ?: 'php://stdout';
        $this->id = $id ?: 'pdo';
    }

    /** @return static */
    public static function define($id, $pdo, $log = null)
    {
        assert(isset(static::$instances[$id]) === false);
        static::$instances[$id] = new static($pdo, $log, $id);
        return static::$instances[$id];
    }

    /** @return void */
    public static function setDefault($id)
    {
        $id = $id instanceof self ? $id->id() : (string) $id;
        assert(empty(static::$instances[$id]) === false);
        static::$instances['_default'] = $id;
    }

    /** @return static */
    public static function instance($id)
    {
        assert(empty(static::$instances[$id]) === false);
        return static::$instances[$id];
    }

    /** @return mixed */
    public static function __callStatic($name, $args)
    {
        assert(empty(static::$instances['_default']) === false);
        $instance = static::instance(static::$instances['_default']);
        return call_user_func_array([$instance, $name], $args);
    }

    /** @return mixed */
    public function __call($name, $args)
    {
        $target = method_exists($this, $name) ? $this : $this->pdo();
        return call_user_func_array([$target, $name], $args);
    }

    /** @return \PDO */
    protected function pdo()
    {
        if ($this->pdo instanceof \Closure) {
            $pdo = $this->pdo;
            $pdo = $pdo();
            assert($pdo instanceof \PDO);
            $this->pdo = $pdo;
            $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        }

        return $this->pdo;
    }

    /** @return string */
    protected function id()
    {
        return $this->id;
    }

    /** @return PDOStatement */
    protected function q($sql, array $params = null)
    {
        $this->log(__METHOD__, $sql, $params);

        if (empty($params)) {
            return $this->pdo()->query($sql);
        }

        // @todo replace placeholders for arrays using IN query and use prepare/execute again.
        // $stmt = $this->pdo()->prepare($sql);
        // $stmt->execute($params);
        $stmt = $this->pdo()->query($this->autoQuote($sql, $params));

        return $stmt;
    }

    /** @return int */
    protected function x($sql, array $params = null)
    {
        $this->log(__METHOD__, $sql, $params);

        if (empty($params)) {
            return $this->pdo()->exec($sql);
        }

        return $this->pdo()->exec($this->autoQuote($sql, $params));
    }

    /** @return array */
    protected function all($sql, array $params = null)
    {
        $stmt = $this->q($sql, $params);
        $rows = $stmt->fetchAll();
        $stmt->closeCursor();
        return $rows;
    }

    /** @return mixed */
    protected function first($sql, array $params = null)
    {
        $stmt = $this->q($sql, $params);
        $row = $stmt->fetch();
        $stmt->closeCursor();
        return $row;
    }

    /** @return mixed */
    protected function column($sql, $column, array $params = null)
    {
        $stmt = $this->q($sql, $params);
        $row = $stmt->fetch(is_int($column) ? \PDO::FETCH_NUM : \PDO::FETCH_ASSOC);
        $stmt->closeCursor();
        $column = strtolower($column);
        $row = array_change_key_case($row, \CASE_LOWER);
        return array_key_exists($column, $row) ? $row[$column] : null;
    }

    protected function transact(callable $callback)
    {
        $pdo = $this->pdo();
        $ret = null;

        $pdo->beginTransaction();

        try {
            $ret = $callback($this);
        } catch (\Exception $e) {
            $pdo->rollBack();
            throw $e;
        } catch (\Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }

        $pdo->commit();

        return $ret;
    }

    /** @return void */
    protected function log($method, $sql, array $params = null)
    {
        if (is_callable($this->log)) {
            call_user_func_array($this->log, func_get_args());
        } else {
            $msg = sprintf(" > %s.%s: %s\n", $method, $this->id(), $this->autoQuote($sql, $params));
            file_put_contents($this->log, $msg);
        }
    }

    /** @return void */
    protected function setLogger(callable $log)
    {
        $this->log = $log;
    }

    /** @return string */
    protected function autoQuote($sql, array $params = null)
    {
        if (empty($params)) {
            return $sql;
        }

        $params = array_values($params);

        $i = strlen($sql);
        $c = count($params);

        if (substr_count($sql, '?') !== $c) {
            throw new \UnexpectedValueException('Number of placeholders and parameters does not match');
        }

        while ($c--) {
            while ($i-- && $sql{$i} !== '?');

            if (is_null($params[$c])) {
                $replace = 'NULL';
            } elseif (is_int($params[$c])) {
                // $replace = $params[$c];
                $replace = $this->pdo()->quote($params[$c]);
            } elseif (is_array($params[$c])) {
                foreach ($params[$c] as &$val) {
                    $val = $this->pdo()->quote($val);
                }

                $replace = sprintf('(%s)', implode(', ', $params[$c]));
            } else {
                $replace = $this->pdo()->quote($params[$c]);
            }

            $sql = substr_replace($sql, $replace, $i, 1);
        }

        return $sql;
    }
}
