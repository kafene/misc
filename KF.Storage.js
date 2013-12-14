/*
// @name KF.Storage
// @description localstorage adapter with expiration, prefixed namespaces.
// @copyright 2013 Kafene Software <http://kafene.org/>
// @example var storage = new KF.storage('myappname');
// @todo - expiration is not yet configurable or working 100%
// THIS IS A WORK IN PROGRESS...
*/
KF.Storage = function (name) {
    if (!name || 'string' != typeof(name)) {
        throw "Name must not be empty.";
        return;
    }

    var self = this;
    var _pro = KF.Storage.prototype;
    var _name = String(name).replace(/[^A-Za-z0-9_]/g, '_').trim();

    var _ls = (function () {
        if (window.localStorage) {
            return window.localStorage;
        } else if (window.globalStorage) {
            return window.globalStorage(document.domain);
        }
    })();


    var _enabled = (undefined != _ls);
    var _stripRe = new RegExp('^' + _name + ':');

    var _empty = {
        key: undefined,
        value: undefined,
        expires: 0,
        type: 'undefined'
    };


    var unprefix = function (key) {
        return String(key).replace(_stripRe, '');
    };


    var prefix = function (key) {
        return _name + ':' + unprefix(key);
    };


    Object.defineProperty(this, 'name', {get: function () {
        return _name;
    }});


    Object.defineProperty(this, 'enabled', {get: function () {
        return _enabled;
    }});


    // Get all item keys [key]
    Object.defineProperty(this, 'keys', {get: function () {
        for (var i = 0, key, ret = []; i < _ls.length; i++)
        {
            if (
                (key = self.key(i)) &&
                0 === key.indexOf(_name + ':')
            ) {
                ret.push(unprefix(key));
            }
        }

        return ret;
    }});


    Object.defineProperty(this, 'length', {get: function () {
        return self.keys.length;
    }});


    // Get all items {key: val}
    Object.defineProperty(this, 'all', {get: function () {
        for (var i = 0, key, ret = {}; i < _ls.length; i++)
        {
            key = self.key(i);

            if (
                key &&
                0 === key.indexOf(_name + ':') &&
                self.has(key)
            ) {
                ret[unprefix(key)] = self.get(key)['value'];
            }
        }

        return ret;
    }});


    _pro.set = function (key, value, ttl) {
        var useTtl = 'number' === typeof(ttl) && isFinite(ttl);

        _ls.setItem(prefix(key), JSON.stringify({
            'key': key,
            'value': value,
            'expires': useTtl ? (+new Date()) + ttl : 0,
            'type': typeof(value)
        }));

        return self;
    };


    _pro.has = function (key) {
        return _ls.hasOwnProperty(prefix(key));
    };


    _pro.get = function (key, getObj) {
        var ret;

        key = prefix(key);

        try {
            ret = JSON.parse(_ls.getItem(key));
        } catch (err) {
            ret = undefined;
        }

        if (ret && self.isExpired(ret)) {
            self.clear(key);
        } else if (ret && ret.value) {
            var v = ret['value'];

            switch (ret['type']) {
                case 'boolean':
                    ret['value'] = 'true' == v;
                    break;
                case 'undefined':
                    ret['value'] = undefined;
                    break;
                case 'number':
                    ret['value'] = Number(v);
                    break;
                case 'object':
                    ret['value'] = v == 'null' ? null : v;
                    break;
            }

            return getObj ? ret : ret['value'];
        }

        return _empty;
    };


    // Check if item/key is expired
    _pro.isExpired = function (key) {
        var data = 'object' == typeof(key)?
            key:
            self.get(prefix(key), true);

        return data && data['expires'] ? data['expires'] < +new Date() : false;
    };


    _pro.key = function (i) {
        return prefix(_ls.key(i));
    };


    // clean up expired values
    _pro.gc = function () {
        self.keys.filter(self.isExpired).forEach(self.clear);
        return self;
    };


    // clear - remove by key, or clear() to remove all.
    _pro.clear = function (key) {
        (undefined !== key)?
            _ls.removeItem(prefix(key)):
            self.keys.forEach(self.clear);

        return self;
    };
};
