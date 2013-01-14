<?php

/**
 * All-in-one BrowserID (aka Mozilla Persona) component.
 * Displays a login link, when clicked, handles the transaction
 * with persona verifier, sets $_SESSION['BrowserIDAuth'] to the user's email.
 * echo BrowserID_Handle('http://example.com/index.php');
 * @param $return to - URL for persona provider to redirect user back to,
    should contain a called instance of this function to continue processing
 * @param $endpoint - BrowserID Consumer to use (e.g. persona.org)
 */
function BrowserID_Handle(
  $return_to = null
, $endpoint = 'https://persona.org/verify'
){
  // my guess here is pretty basic so you should probably pass this param in.
  if(!$return_to)
    $return_to = '//'.getenv('SERVER_NAME').getenv('REQUEST_URI');
  // Start a session if none active. you should probably have one started.
  if(session_status() != \PHP_SESSION_ACTIVE)
    session_start();
  // Handle request to log out
  if(isset($_REQUEST['BrowserIDDestroy'])) {
    $_SESSION['BrowserIDAuth'] = false;
    unset($_SESSION['BrowserIDAuth']);
    exit(header("Location: $return_to"));
  }
  // Handle request to log in
  elseif(isset($_POST['BrowserIDAssertion'])) {
    $audience  = getenv('HTTP_HOST');
    $assertion = $_POST['BrowserIDAssertion'];
    $query = array('audience' => $audience, 'assertion' => $assertion);
    $ctx['method']  = 'POST';
    $ctx['header']  = 'Content-Type: application/x-www-form-urlencoded';
    $ctx['content'] = http_build_query($query);
    $stream_context['http'] = $ctx;
    $stream = stream_context_create($stream_context);
    if(false === $res = file_get_contents($endpoint, false, $stream)) {
      throw new \Exception('['.$endpoint.']: No Response');
    } elseif(false === ($json = json_decode($res))) {
      throw new \Exception('['.$endpoint.']: Parsing Response JSON Failed.');
    } elseif(!isset($json->status) || $json->status == 'failure') {
      $reason = empty($json->reason)
        ? 'Reason unavailable.'
        : $json->reason;
      throw new \Exception('['.$endpoint.']: '.$reason);
    } else {
      if($json->status == 'okay' && isset($json->email)) {
        $_SESSION['BrowserIDResponseJSON'] = $json;
        $_SESSION['BrowserIDAuth'] = $json->email;
      } else {
        $_SESSION['BrowserIDAuth'] = false;
        unset($_SESSION['BrowserIDAuth']);
      }
      // Redirect to continue processing.
      exit(header('Location: '.$return_to));
    }
  }
  // Last case, return HTML forms.
  else {
    // Log-out form if logged in
    if(isset($_SESSION['BrowserIDAuth'])) {
      $u = $_SESSION['BrowserIDAuth'];
      return '<form method="post" id="BrowserIDLogout">
      <input type="submit" name="BrowserIDDestroy" value="Log Out ['.$u.']">
      </form>';
    }
    // Log-in form if not logged in
    return '<form id="BrowserIDLogin" method="POST" action="'.$return_to.'">
    <input id="BrowserIDAssertion" type="hidden" name="BrowserIDAssertion">
    <script src="https://login.persona.org/include.js"></script>
    <script>function BrowserIDVerify() {
      navigator.id.get(function(assertion) {
        if(assertion) {
          document.getElementById("BrowserIDAssertion").value = assertion;
          document.getElementById("BrowserIDLogin").submit();
        } else { alert("BrowserID Assertion Failed."); }
    });}</script>
    <a href="#" onclick="BrowserIDVerify();">Log In [Persona]</a>
    </form>';
  }
}
