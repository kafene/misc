<?php

# Shorten a URL using Google's goo.gl API. Requires an API key.
function googl_shorten($url, $api_key, $endpoint = null) {
    $endpoint = $endpoint ?: 'https://www.googleapis.com/urlshortener/v1';
    $ch = curl_init(sprintf('%s/url?key=%s', $endpoint, $api_key));
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_AUTOREFERER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode(['longUrl' => $url]),
    ]);
    $result = curl_exec($ch);
    curl_close($ch);
    return json_decode($result);
}

# Pygmentize $code using the remote service available at pygments.appspot.com
function pygmentize($lang, $code) {
    list($uri, $method) = ['http://pygments.appspot.com/', 'POST'];
    $content = join('&', array_map('rawurlencode', compact('lang', 'code')));
    $c = stream_context_create(['http' => compact('method', 'content')]);
    return file_get_contents($uri, null, $c);
}

# Markdown $text with GitHub's APi
function github_markdown($text, $gfm = true, $context = null) {
    $uri = 'https://api.github.com/markdown';
    $mode = $gfm ? 'gfm' : 'markdown';
    $data = array_filter(compact('text', 'mode', 'context'));
    $c = stream_context_create(['http' => [
        'header' => 'Content-Type: application/json',
        'method' => 'POST',
        'content' => json_encode($data),
    ]]);
    return file_get_contents($uri, null, $c);
}
