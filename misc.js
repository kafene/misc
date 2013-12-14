/*
// @namespace 2A996644635811E386E94397A24410D2
// @copyright (c) 2013 kafene software <http://kafene.org/>
*/
var KF = {};

// markdown w/ marked on load
KF['markedOnLoad'] = function () {
    document.addEventListener('DOMContentLoaded', function () {
        if ('function' != typeof(marked)) return;
        // html-escape <pre><code> stuff beforehand so it displays okay.
        [].forEach.call(document.querySelectorAll('.md pre code'), function (e) {
            var d = document.createElement('div');
            d.innerHTML = e.innerHTML;
            e.innerHTML = d.innerHTML;
        });
        [].forEach.call(document.querySelectorAll('.md'), function (e) {
            try { e.innerHTML = marked(e.innerHTML); } catch (a) {}
        });
    });
};



KF['toArray'] = function (arr) {
    if (Array.isArray(arr)) {
        return arr;
    } else if (arr.length) {
        for (var i = 0, ret = []; i < arr['length']; i++) {
            ret.push(arr[i]);
        }
        return ret;
    } else if ('object' == typeof(arr)) {
        return [].slice.call(arr);
    } else {
        return [arr];
    }
};



// call callback on each value in obj
// do callback to everything in obj
KF['each'] = function (obj, callback) {
    if (obj.length) {
        for (var i = 0; i < obj.length; i++) {
            callback(obj[i], i, obj);
        }
    } else if ('object' == typeof(obj)) {
        for (var i in obj) {
            callback(obj[i], i, obj);
        }
    } else {
        callback(obj);
    }
}



// apply callback to each value in obj, return array of callback return vals.
KF['collect'] = function (obj, callback) {
    var ret = [];
    KF.each(obj, function (v, k, obj) {
        ret.push(callback(v, k, obj));
    });
    return ret;
};



KF['unique'] = function (obj) {
    var obj = KF.toArray(obj);
    return obj.reverse().filter(function (v, k, obj) {
        return -1 === obj.indexOf(v, k + 1);
    }).reverse();
};



KF['values'] = function (obj) {
    return KF.collect(obj, function (v) { return v; });
};



KF['keys'] = function (obj) {
    KF.collect(obj, function (v, k) { return k; });
};



KF['pairs'] = function (obj) {
    KF.collect(obj, function (v, k) { return [k, v]; });
};



KF['getParameters'] = function (qs) {
    var ret = {}, qs = qs || window.location.search;
    qs.replace(/[?&]+([^=&]+)=?([^&]*)/gi, function(m, k, v) {
        ret[k] = decodeURIComponent(v).replace(/\+/g, ' ');
    });
    return ret;
};



KF['jsonParse'] = function (str) {
    try { return JSON.parse(str); } catch (a) { return null; }
};



KF['jsonStringify'] = function (obj) {
    try { return JSON.stringify(obj); } catch (a) { return null; }
};



KF['random'] = function (len) {
    var ret = '';
    while (ret.length < len) {
        ret += Math.random().toString(36).substring(2);
    }
    return ret.substring(0, len);
};



KF['regExpEscape'] = function (str) {
    return String(str).replace(/[\\.\+*?\[^\]$(){}=!<>|:\-]/g, '\\$&');
};


KF['htmlEntityDecode'] = function (str) {
    var div = document.createElement('div');
    div.innerHTML = str;
    return div.innerHTML;
};



KF['mixin'] = function (srcObj, obj) {
    for (var i in srcObj) {
        if (srcObj.hasOwnProperty(i)) {
            obj[i] = srcObj(i);
        }
    }
    return obj;
};



// Parse a string of response headers into a key/value object.
KF['parseResponseHeaders'] = function (headers) {
    var ret = {}, kv, key, value;
    String(headers).split(/\r?\n/).map(function (line) {
        return String(line).trim();
    }).filter(function (line) {
        return line.length > 0 && /:/.test(line);
    }).forEach(function (line) {
        kv = /^([^:]+):\s*(.*)$/.exec(line);
        key = kv[1].trim();
        value = kv[2].trim();
        // Same header appearing more than once - use array
        // @maybe change this to joining by a comma and quoting other commas?
        if (ret[key]) {
            if (!Array.isArray(ret[key])) {
                ret[key] = [ret[key]];
            }
            ret[key].push(value);
        } else {
            ret[key] = value;
        }
    });
    return ret;
};



// Get response headers from some URL,
// return them parsed into a key/value object.
KF['getResponseHeaders'] = function (url) {
    var headers, req = new XMLHttpRequest();
    req.open('GET', url || document.URL, false);
    req.send(null);
    headers = req.getAllResponseHeaders() || null;
    return headers ? parseResponseHeaders(headers) : null;
};



KF['injectCss'] = function (css) {
    var style;
    if ('string' === typeof(css)) {
        style = document.createElement('style');
        css = css.replace(/<\/?style[^>]*>/ig, '');
        style.type = 'text/css';
        style.textContent = css;
    } else {
        style = css;
    }
    if (document.head) {
        document.head.appendChild(style);
    } else if (document.body) {
        document.body.insertAdjacentElement('afterbegin', style);
    } else {
        document.documentElement.appendChild(style);
    }
};



KF['merge'] = function (dest, src) {
    var srcs = [].slice.call(arguments, 1);
    if ('object' != typeof(dest)) {
        throw 'KF.merge: source/destination must be objects.';
    }
    for (var i in src) {
        if (!src.hasOwnProperty(i)) continue;
        dest[i] = src[i];
    }
    return src;
};



KF['parseUrl'] = function (url) {
    if (!/\/\//.test(url)) return url;
    var a = document.createElement('a');
    a.href = url;
    return a;
};



KF['define'] = function (scope, name, definition) {
    if ('undefined' != typeof(module) && module.exports) {
        module.exports = definition();
    } else if ('function' == typeof('define') && define.amd) {
        define(definition);
    } else if (scope instanceof Window || scope instanceof window.Window) {
        if ('object' == typeof(window.wrappedJSObject)) {
            window.wrappedJSObject[name] = definition();
        } else if ('object' == typeof(unsafeWindow)) {
            unsafeWindow[name] = definition();
        } else if (window.opera) {
            window.opera.defineMagicVariable(name, function () {
                return definition();
            }, null);
        }
        scope[name] = definition();
    } else {
        scope[name] = definition();
    }
};



KF['sprintf'] = function (str) {
    var args = [].slice.call(arguments).slice(1);
    return str.replace(/%s/g, function () {
        return args.shift();
    });
};



KF['await'] = function (testFn, readyFn) {
    testFn() ? readyFn() : setTimeout(function() {
        KF.await(testFn, readyFn);
    }, 9);
};



