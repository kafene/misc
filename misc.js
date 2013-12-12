// Parse a string of response headers into a key/value object.
function parseResponseHeaders(headers) {
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
}



// Get response headers from some URL,
// return them parsed into a key/value object.
function getResponseHeaders(url) {
    var headers, req = new XMLHttpRequest();

    req.open('GET', url || document.URL, false);
    req.send(null);
    headers = req.getAllResponseHeaders() || null;

    return headers ? parseResponseHeaders(headers) : null;
};



// do callback to everything in obj
function each(obj, callback) {
    if (undefined === obj || null === obj) {
        return;
    }
    if (obj.hasOwnProperty('length')) {
        for (var i = 0; i < obj.length; i++) {
            callback(obj[i], i, obj);
        }
    } else if ('object' == typeof(obj)) {
        for (var i in obj) {
            if (obj.hasOwnProperty(i)) {
                callback(obj[i], i, obj);
            }
        }
    } else {
        callback(obj);
    }
}



// markdown w/ marked on load
function markedOnload() {
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



// export to define.amd, module.exports, or `context` (usually `this` (`window`))
KF.export = function (name, context, definition) {
    if ('undefined' != typeof(module) && module['exports']) {
        module.exports = definition();
    } else if ('function' == typeof(define) && define['amd']) {
        define(definition);
    } else {
        context[name] = definition();
    }
};
