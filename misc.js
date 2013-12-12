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
