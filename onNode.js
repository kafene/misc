/*
 * Persistently monitor for nodes matching a CSS selector,
 * and run a given callback on all nodes that match that
 * selector, beginning from the time the DOM is loaded,
 * or immediately if it is already loaded, and during any
 * `DOMNodeInserted` events.
 */

var onNode;
(KF || {})['onNode'] = onNode = (function () {
    /* Element.matches */
    var matchesSelector = (function () {
        var prot = window.Element.prototype;
        var func;
        if (prot.matches) {
            return prot.matches;
        } else if (prot.matchesSelector) {
            return prot.matchesSelector;
        } else if (prot.mozMatchesSelector) {
            return prot.mozMatchesSelector;
        } else if (prot.msMatchesSelector) {
            return prot.msMatchesSelector;
        } else if (prot.oMatchesSelector) {
            return prot.oMatchesSelector;
        } else if (prot.webkitMatchesSelector) {
            return prot.webkitMatchesSelector;
        } else {
            return function (node, selector) {
                var parent = node.parentNode || node.document;
                var nodes = parent.querySelectorAll(selector);
                var i = -1;
                while (nodes[++i] && nodes[i] != node);
                return !!nodes[i];
            };
        }
    })();

    var onLoad = (function () {
        var callbacks;
        var isLoaded = /^loaded|complete/i.test(document.readyState);
        document.addEventListener('DOMContentLoaded', function loadFunc() {
            document.removeEventListener('DOMContentLoaded', loadFunc);
            isLoaded = true;
            var callback;
            while (callback = callbacks.shift()) callback();
        }, false);
        return function (callback) {
            isLoaded ? callback() : callbacks.push(callback);
        }
    });

    function processNode(node, selector) {
        /* `node` is an event object, get target element. */
        if (node instanceof window.Event) {
            if (node.target) {
                node = node.target;
            } else if (node.srcElement) {
                node = node.srcElement;
            } else {
                return;
            }
        }
        /* `node` is an html element, check if matches selector, run callback */
        if (
            (node instanceof window.HTMLElement) &&
            !/^script|style|template$/i.test(node.tagName) &&
            matchesSelector(node, selector)
        ) {
            callback(node);
        }
        /* `node` can `querySelectorAll`, process all matching children in node. */
        if (node.querySelectorAll) {
            [].forEach.call(node.querySelectorAll(selector), function (e) {
                processNode(e, selector);
            });
        }
    };
    return function (selector, callback) {
        document.addEventListener('DOMNodeInserted', function (e) {
            processNode(e, selector);
        });
        onLoad(function () {
            processNode(document, selector);
        });
    };
})();
