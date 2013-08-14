<?php

class jsonResponse implements \jsonSerializable
{
    /**
     * Response Message - sent as a top-level 'message' parameter.
     *
     * @var string
     */
    protected $message = '';

    /**
     * Response HTTP status code
     *
     * @var integer
     */
    protected $status = 200;


    /**
     * JSON-encoding flags to use when sending.
     * If left null, PHP default flags will be used.
     *
     * @var integer
     */
    protected $flags = null;


    /**
     * If the response is an error response.
     *
     * @var boolean
     */
    protected $error = false;


    /**
     * Additional response parameters/data.
     *
     * @var array
     */
    protected $data = [];



    /**
     * Initialize with some data or a message.
     * Starts an output buffer if none is started to avoid accidental output.
     *
     * @param string|array $data Message or Data
     * @throws InvalidArgumentException If $data is effed up.
     * @return static $this
     */
    function __construct($data = null)
    {
        if (!ob_get_level()) {
            ob_start();
        }
        if (is_string($data)) {
            $this->message = $data;
            return $this;
        }
        if (is_object($data)) {
            if (method_exists($data, 'getArrayCopy')) {
                $data = $data->getArrayCopy();
            } elseif (method_exists($data, 'toArray')) {
                $data = $data->toArray();
            } elseif ($data instanceof Traversable) {
                $data = iterator_to_array($data);
            } else {
                $data = get_object_vars($data);
            }
        }
        if (is_array($data)) {
            if (isset($data['message'])) {
                $this->__set('message', $data['message']);
                unset ($data['message']);
            }
            if (isset($data['status'])) {
                $this->__set('status', $data['status']);
                unset ($data['status']);
            }
            if (isset($data['flags'])) {
                $this->__set('flags', $data['flags']);
                unset ($data['flags']);
            }
            if (isset($data['error'])) {
                $this->__set('error', $data['error']);
                unset ($data['error']);
            }
            if (isset($data['data']) && is_array($data['data'])) {
                $data = $data['data'];
            }
            $this->__set('data', $data);
        } elseif (null !== $data) {
            throw new InvalidArgumentException('Data must be either an Array or String.');
        }
        return $this;
    }

    static function create($data = null) {
        return new static($data);
    }

    /**
     * Allow for callable properties, e.g. $response->message('Hello!');
     * Can only be used to set class vars - not vars in the $data array.
     *
     * @param scalar $i Property name/key
     * @throws BadMethodCallException If the property name is not a class var.
     * @param mixed $v Property value
     * @return mixed Result of __get() or __set()
     */
    function __call($i, $v)
    {
        if (property_exists($this, $i)) {
            if (empty($v)) {
                return $this->__get($i);
            } else {
                return $this->__set($i, $v);
            }
        } else {
            throw new BadMethodCallException;
        }
    }

    /**
     * Set a param/value.
     *
     * @param scalar $i Parameter Name
     * @param scalar $v Parameter Value
     * @throws InvalidArgumentException If you done goofed.
     * @return null
     */
    function __set($i, $v)
    {
        switch (strtolower($i)) {
            case 'message':
                $this->message = (string) $v;
                break;
            case 'status':
                if (!is_int($v) || ($v < 100 || $v >= 600)) {
                    throw new \InvalidArgumentException('Invalid Status Code.');
                }
                $this->status = (int) $v;
                break;
            case 'flags':
                if (!is_int($v)) {
                    throw new \InvalidArgumentException('Flags Must be an Integer.');
                }
                $this->flags = $v;
                break;
            case 'error':
                if (!is_bool($v)) {
                    throw new \InvalidArgumentException('Error must be Boolean.');
                }
                $this->error = (bool) $v;
                break;
            case 'data':
                if (!is_array($v)) {
                    throw new \InvalidArgumentException('Data must be an Array.');
                }
                $this->data = (array) $v;
                break;
            default:
                $this->data[$i] = $v;
                break;
        }
    }

    /**
     * Unset a parameter.
     * If the param is a class variable, reset it to its default state.
     *
     * @param scalar $i Parameter name to unset.
     * @return null
     */
    function __unset($i)
    {
        switch (strtolower($i)) {
            case 'message':
                $this->message = '';
                break;
            case 'status':
                $this->status = 200;
                break;
            case 'flags':
                $this->flags = null;
                break;
            case 'error':
                $this->error = false;
                break;
            case 'data':
                $this->data = [];
                break;
            default:
                unset ($this->data[$i]);
                break;
        }
    }

    /**
     * Check if a parameter or class variable is set.
     * If using a class variable, it will perform looser checks.
     *
     * @param scalar $i Parameter name to check
     * @return boolean
     */
    function __isset($i)
    {
        switch (strtolower($i)) {
            case 'message':
                return !empty($this->message);
            case 'status':
                return (bool) $this->status;
            case 'flags':
                return null !== $this->flags;
            case 'error':
                return true === $this->error;
            case 'data':
                return !empty($this->data);
            default:
                return array_key_exists($i, $this->data);
        }
    }

    /**
     * Retrieve a parameter from the class.
     * First returns class variables then any variables
     * set as a top-level key in $data.
     *
     * @param scalar $i Parameter name to get.
     * @return mixed Whatever was got or null.
     */
    function __get($i)
    {
        switch (strtolower($i)) {
            case 'message':
                return (string) $this->message;
            case 'status':
                return (int) $this->status;
            case 'flags':
                return (int) $this->flags;
            case 'error':
                return (bool) $this->error;
            case 'data':
                return (array) $this->data;
            default:
                if (isset($this->data[$i])) {
                    return $this->data[$i];
                }
        }
    }

    /**
     * Clear a class or $data variable by name, or all class variables.
     * If no arguments are given, all parameters will be cleared.
     *
     * @param string $i Variable name to reset/clear
     * @return static $this
     */
    function clear($i = null)
    {
        $all = 0 === func_num_args();
        $lcv = strtolower($i);
        if ($all || 'message' == $lcv) {
            $this->__unset('message');
        }
        if ($all || 'status' == $lcv) {
            $this->__unset('status');
        }
        if ($all || 'flags' == $lcv) {
            $this->__unset('flags');
        }
        if ($all || 'error' == $lcv) {
            $this->__unset('error');
        }
        if ($all || 'data' == $lcv) {
            $this->__unset('data');
        }
        if (!$all) {
            $this->__unset($i);
        }
        return $this;
    }

    /**
     * Sends the response.
     * Wipes any existing output.
     *
     * @param boolean $exit Whether to exit after sending.
     * @return scalar $this Unless program has exited, natch.
     */
    function send($exit = true)
    {
        while (ob_get_level()) {
            ob_end_clean();
        }
        http_response_code($this->__get('status'));
        if (!headers_sent()) {
            header('Content-Type: application/json');
        }
        $data = (null !== $this->flags)
            ? json_encode($this, $this->flags)
            : json_encode($this);
        print $data;
        flush();
        if ($exit) {
            exit;
        }
        return $this;
    }

    /**
     * Implement jsonSerializable
     *
     * @return array Class variables and data.
     */
    function jsonSerialize()
    {
        $data = (array) $this->__get('data');
        $data['message'] = $this->__get('message');
        $data['status'] = $this->__get('status');
        $data['error'] = $this->__get('error');
        return $data;
    }
}
