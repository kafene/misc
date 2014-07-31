
function random(len) {
    var ret = '';
    while (ret.length < len) ret += Math.random().toString(36).substring(2);
    return ret.substring(0, len);
};



// Parse a string of response headers into a key/value object.
function parseHeaders(headers) {
    var ret = {};

    String(headers).split(/\r?\n/).map(function (line) {
        return String(line).trim();
    }).filter(function (line) {
        return line.length > 0 && /:/.test(line);
    }).forEach(function (line) {
        var kv = /^([^:]+):\s*(.*)$/.exec(line);
        var key = kv[1].trim();
        var value = kv[2].trim();

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
    return headers ? parseHeaders(headers) : {};
}



function define(scope, name, definition) {
    if ('undefined' != typeof(module) && module.exports) {
        module.exports = definition();
    } else if ('function' == typeof('define') && define.amd) {
        define(definition);
    } else {
        scope[name] = definition();
    }
}



function heredoc(fn) {
    return (fn.toString()
        .replace(/(^[^\/]+\/\*!?)|/, '')
        .replace(/\*\/[^\/]+$/, ''));
}



function htmlEncode(str) {
    return (String(str)
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;'));
}



function htmlDecode(str) {
    var div = document.createElement('div');
    div.innerHTML = str;
    return div.textContent;
}



function format(str, args) {
    for (var a in args) {str = str.replace(new RegExp('\\{'+a+'\\}'), args[a])}
    return str;
}



function when(t, f) {
    t() ? f() : setTimeout(function () {when(t, f)}, 9);
}



function parseKvData(kvstr, delim, split, obj) {
    var d = delim || '&', s = split || '=', acc = false === obj ? [] : {};

    kvstr.split(d).forEach(function (i) {
        var p = i.split(s);
        acc.push ? acc.push(p) : (acc[p[0]] = p[1]);
    });

    return acc;
}



// is_a(window, 'Window');
// is_a(document.createElement('a'), 'window.HTMLAnchorElement')
function is_a(thing, obj) {
    if (('string' === typeof (obj)) && obj.toLowerCase() !== 'string') {
        return (thing instanceof eval(obj));
    } else {
        return (thing instanceof obj);
    }
}



// http://is.gd/mwZp7E
function walkTextNodes(node, callback) {
    var child, next;
    switch (node.nodeType) {
        case 1:  // Node.ELEMENT_NODE
        case 9:  // Node.DOCUMENT_NODE
        case 11: // Node.DOCUMENT_FRAGMENT_NODE
            child = node.firstChild;
            while (child) {
                next = child.nextSibling;
                walk(child, callback);
                child = next;
            }
            break;
        case 3: // Node.TEXT_NODE
            callback(node);
            break;
    }
}



function values(obj, onlyOwnProperties) {
    var acc = [];
    for (var i in obj) {
        if (false === onlyOwnProperties || obj.hasOwnProperty(i)) {
            acc.push(obj[i]);
        }
    }
    return acc;
};



function uniq(arr) {
    return arr.reverse().filter(function (e, i, arr) {
        return arr.indexOf(e, i + 1) === -1;
    }).reverse();
}



function regexEscape(str) {
    return (str || '').replace(/[-\/\\^$*+?.()|[\]{}=!<>:]/g, '\\$&');
}



// break 'www.example.com' into ["com", "example.com", "www.example.com"]
function subdomains(hostame) {
    (hostname || location.hostname).split(/\./).map(function (e, i, arr) {
        return arr.slice(i).join('.');
    }).reverse();
}



// integer or integer string > 0
function isNatural(n) {
    return isFinite(n = Number(n)) && /^[0-9]+$/.test(n) && n > 0;
}



String.prototype.startsWith = String.prototype.startsWith || function (prefix) {
    return this.slice(0, prefix.length) === prefix;
};



String.prototype.endsWith = String.prototype.endsWith || function (suffix) {
    return this.indexOf(suffix, this.length - suffix.length) !== -1;
};



// polyfill for Element.matches
(function (obj) {
    var matches = (
        obj.matches ||
        obj.matchesSelector ||
        obj.mozMatchesSelector ||
        obj.msMatchesSelector ||
        obj.oMatchesSelector ||
        obj.webkitMatchesSelector ||
        function (selector) {
            var nodes = (this.parentNode || this.document).querySelectorAll(selector), i = -1;
            while (nodes[++i] && nodes[i] !== this);
            return !!nodes[i];
        }
    );
    if (!obj.matches) { obj.matches = matches; }
    if (!obj.matchesSelector) { obj.matchesSelector = matches; }
})(window.Element.prototype);



// jQuery selector to match exact text inside an element
// http://wowmotty.blogspot.com/2010/05/jquery-selectors-adding-contains-exact.html
// :regex() - set by user ( use: $(':regex("/(red|blue|yellow)/gi")') )
$.extend($.expr[':'], {regex: $.expr.createPseudo(function (text) {
    var m = /^\/((?:\\\/|[^\/])+)\/([mig]{0,3})$/.exec(text);
    return function (el) {
        var elText = el.textContent || el.innerText || $(el).text();
        return m ? (new RegExp(m[1], m[2]).test($.trim(elText))) : false;
    };
})});


