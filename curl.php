<?php

function curl_request(array $opt = []) {
    $opt = array_merge([
        "URL" => "",
        "METHOD" => "GET",
        "COOKIEJAR" => sys_get_temp_dir().DIRECTORY_SEPARATOR."curl_cookiejar.txt",
        "CURLOPTS" => [],
        "DATA" => [],
        "CAFILE" => stream_resolve_include_path("cacert.pem"),
        "REFERER" => "",
        "USERAGENT" => empty($_SERVER["HTTP_USER_AGENT"])
            ? "Curl/PHP ".PHP_VERSION." (http://github.com/shuber/curl)"
            : $_SERVER["HTTP_USER_AGENT"],
        "HEADERS" => ["Connection: Close"],
    ], array_change_key_case($opt, CASE_UPPER));

    $opt["URL"] = filter_var($opt["URL"], FILTER_VALIDATE_URL);

    if (!$opt["URL"]) {
        throw new \InvalidArgumentException("Invalid URL.");
    }

    $opt["METHOD"] = strtoupper($opt["METHOD"]);

    # Build data array into HTTP Query
    $opt["DATA"] = (sizeof($opt["DATA"]) > 0)
            ? http_build_query($opt["DATA"], "", "&")
            : "";

    # If we have a cacert.pem
    $opt["CAFILE"] = $opt["CAFILE"] && is_readable($opt["CAFILE"])
            ? $opt["CAFILE"]
            : null;

    $IS_GET = in_array($method, ["HEAD", "GET"]);
    $IS_CUSTOM = !$IS_GET && "POST" != $opt["METHOD"]; # Not GET/HEAD/POST

    # Attach data array to url?
    if (!empty($opt["DATA"]) && $IS_GET) {
        $opt["URL"] .= strpos($opt["URL"], "?") ? "&" : "?").$opt["DATA"];
        $opt["DATA"] = "";
    }

    $curl = curl_init();
    $result = [
        "error" => 0,
        "response" => "",
        "body" => "",
        "headers" => [],
        "status" => 0,
    ];

    curl_setopt_array($curl, array_filter(array_merge([
        CURLOPT_URL => $opt["URL"],
        CURLOPT_NOBODY => "HEAD" == $opt["METHOD"] ? true : null,
        CURLOPT_HTTPGET => "GET" == $opt["METHOD"] ? true : null,
        CURLOPT_POST => "POST" == $opt["METHOD"] ? true : null,
        CURLOPT_CUSTOMREQUEST => $IS_CUSTOM ? $opt["METHOD"] : null,
        CURLOPT_POSTFIELDS => $IS_GET ? null : $opt["DATA"],
        CURLOPT_HEADER => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERAGENT => $opt["USERAGENT"] ?: null,
        CURLOPT_COOKIEFILE => $opt["COOKIEJAR"] ?: null,
        CURLOPT_COOKIEJAR => $opt["COOKIEJAR"] ?: null,
        CURLOPT_CAINFO => empty($opt["CAFILE"]) ? null : $opt["CAFILE"],
        CURLOPT_SSL_VERIFYPEER => empty($opt["CAFILE"]) ? null : true,
        CURLOPT_SSL_VERIFYHOST => empty($opt["CAFILE"]) ? null : 2,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_REFERER => $opt["REFERER"] ?: null,
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_AUTOREFERER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_HTTPHEADER => empty($opt["HEADERS"]) ? null : $opt["HEADERS"],
    ], $opt["CURLOPTS"])));

    $result["response"] = curl_exec($this->curl);

    if (!$result["response"]) {
        $result["error"] = curl_errno($curl)." - ".curl_error($curl);
    } else {
        $headerPattern = '#HTTP/\d\.\d.*?$.*?\r\n\r\n#ims';
        preg_match_all($headerPattern, $result["response"], $m);
        $headerString = array_pop($m[0]);
        $headers = explode("\r\n", str_replace("\r\n\r\n", '', $headerString));
        $result["body"] = str_replace($headerString, "", $result["response"]);
        $httpStatus = array_shift($headers);
        preg_match('/HTTP\/(\d\.\d)\s(\d{3})\s(.*)/', $httpStatus, $m);
        $result["status"] = $m[2]; # status code
        $result["headers"]["Status"] = $httpStatus;
        foreach ($headers as $header) {
            if (preg_match('#(.*?)\:\s(.*)#', $header, $m)) {
                $result["headers"][$m[1]] = $m[2];
            }
        }
    }

    curl_close($curl);
  
    return $result;
}
