<?php

/**
 * Glovebox: Lightweight Dependency Injection Container
 * @author    Michael Squires <sqmk@php.net>
 * @copyright Copyright (c) 2012 Michael K. Squires
 * @license   http://github.com/sqmk/Glovebox/wiki/License
 * @package   Glovebox
 */
class Glovebox implements \ArrayAccess {
  protected $services = [], $parameters = [];
  function getServices() {
    return array_keys($this->services);
  }
  function getParameters() {
    return array_keys($this->parameters);
  }
  function __get($service) {
    if(!$this->__isset($service))
      throw new \DomainException("Unknown service: {$service}");
    $service = $this->services[$service];
    if(!($service->value instanceof \Closure))
      return $service->value;
    return $service->persist === true
      ? $service->value = call_user_func_array($service->value, array($this))
      : call_user_func_array($service->value, [$this]);
  }
  function __set($service, \Closure $factory) {
    $this->services[$service] = (object)array(
        'value'=>$factory
      , 'persist'=>false
    );
  }
  function __isset($service) {
    return array_key_exists($service, $this->services);
  }
  function __unset($service) {
    unset($this->services[$service]);
  }
  function __invoke($service) {
    if(!$this->__isset($service))
      throw new \DomainException("Unknown service: {$service}");
    return $this->services[$service];
  }
  function offsetExists($k) {
    return array_key_exists($k, $this->parameters);
  }
  function offsetGet($k) {
    if(!$this->offsetExists($k))
      throw new \DomainException("Unknown parameter: {$k}");
    return $this->parameters[$k];
  }
  function offsetSet($k, $v) {
    $this->parameters[$k] = $v;
  }
  function offsetUnset($k) {
    unset($this->parameters[$k]);
  }
}
