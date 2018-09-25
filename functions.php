<?php
 function dkim_init()
 {
  $ok = false;
  if (@include_once(SM_PATH . 'config/config_dkim.php'))
   $ok = true;
  elseif (@include_once(SM_PATH . 'plugins/dkim/config.php'))
   $ok = true;
  elseif (@include_once(SM_PATH . 'plugins/dkim/config_default.php'))
   $ok = true;
  return $ok;
 }

 function dkim_check_configuration_do()
 {
  global $openssl_cmds;
  global $tmp_dir;
  if (!check_sm_version(1, 5, 2))
  {
   if (check_sm_version(1, 4, 10) && !check_sm_version(1, 5, 0))
   { /* no-op */ }
   else
   {
    if (function_exists('check_plugin_version') && check_plugin_version('compatibility', 2, 0, 7, true))
    { /* no-op */ }
    else
    {
     do_err('DKIM Verification plugin requires the Compatibility plugin version 2.0.7+', false);
     return true;
    }
   }
  }
  if (!dkim_init())
  {
   do_err('DKIM Verification plugin is missing its main configuration file', false);
   return true;
  }
  $res = exec("$openssl_cmds --version", $output, $retval);
  if ($retval)
  {
   do_err('DKIM Verification plugin had a problem executing the openssl program at ./openssl-cmds.sh: '.$res, false);
   return true;
  }
  if (preg_match("/^OpenSSL.*1\.0\.[1-9]/", $res) == 0)
  {
   do_err('DKIM Verfication plugin requires a newer release of openssl, actual release: '.$res.'.', false);
   return true;
  }
  if (!is_dir($tmp_dir) || !is_readable($tmp_dir) || !is_writable($tmp_dir))
  {
   do_err('DKIM Verification plugin temporary directory ($tmp_dir) is not properly configured ('.$tmp_dir.')', false);
   return true;
  }
  return false;
 }

 function dkim_dns_record($host, &$acceptedHashes, &$strict)
 {
  $acceptedHashes = null;
  $strict = false;
  $ret = dns_get_record($host, DNS_TXT);
  if ($ret === false)
   return false;
  if (count($ret) < 1)
   return false;
  foreach ($ret as $tRet)
  {
   $record = $tRet['txt'];
   $recVals = array();
   if (strpos($record, ';') !== false)
   {
    $recLine = explode(';', $record);
    foreach ($recLine as $kv)
    {
     if (empty($kv))
      continue;
     if (strpos($kv, '=') === false)
      continue;
     list($lKey, $lVal) = explode('=', $kv, 2);
     $recVals[strtolower(str_replace(' ', '',$lKey))] = str_replace(' ',  '', $lVal);
    }
   }
   else
   {
    if (empty($record))
     continue;
    if (strpos($record, '=') === false)
     continue;
    list($lKey, $lVal) = explode('=', $record, 2);
    $recVals[strtolower(str_replace(' ', '',$lKey))] = str_replace(' ',  '', $lVal);
   }
   if (!array_key_exists('p', $recVals))
    continue;
   if (array_key_exists('v', $recVals) && $recVals['v'] !== 'DKIM1')
    continue;
   if (array_key_exists('s', $recVals))
   {
    $services = array();
    if (strpos($recVals['s'], ':') === false)
     $services[] = $recVals['s'];
    else
     $services = explode(':', $recVals['s']);
    if (!in_array('*', $services) && !in_array('email', $services))
     continue;
   }
   if (array_key_exists('h', $recVals))
   {
    $hashTypes = array();
    if (strpos($recVals['h'], ':') === false)
     $hashTypes[] = $recVals['h'];
    else
     $hashTypes = explode(':', $recVals['h']);
    $acceptedHashes = $hashTypes;
   }
   if (array_key_exists('t', $recVals))
   {
    $flags = array();
    if (strpos($recVals['t'], ':') === false)
     $flags[] = $recVals['t'];
    else
     $flags = explode(':', $recVals['t']);
    if (in_array('s', $flags))
     $strict = true;
   }
   $record = substr($record, strpos($record, 'p=') + 2);
   if (strpos($record, ';') !== false)
    $record = substr($record, 0, strpos($record, ';'));
   $record = wordwrap($record, 64, "\r\n", true);
   return "-----BEGIN PUBLIC KEY-----\r\n$record\r\n-----END PUBLIC KEY-----\r\n";
  }
  return false;
 }

 function dkim_canon_body($canon, $body, $length)
 {
  if ($canon === 'r')
  {
   while (strpos($body, " \r\n") !== false)
    $body = str_replace(" \r\n", "\r\n", $body);
   while (strpos($body, "\t") !== false)
    $body = str_replace("\t", " ", $body);
   while (strpos($body, "  ") !== false)
    $body = str_replace("  ", " ", $body);
   while (substr($body, -2) === "\r\n")
    $body = substr($body, 0, -2);
   if (!empty($body))
    $body.= "\r\n";
   if ($length === -1)
    $length = strlen($body);
   return substr($body, 0, $length);
  }
  while (substr($body, -2) === "\r\n")
   $body = substr($body, 0, -2);
  $body.= "\r\n";
  if ($length === -1)
   $length = strlen($body);
  return substr($body, 0, $length);
 }

 function dkim_canon_header($canon, $headers, $aHOrder)
 {
  global $message;
  $aHOrder[] = "DKIM-Signature";
  $hRet = "";
  if ($canon === 'r')
  {
   $hdrs = array();
   foreach ($message->rfc822_header->raw_headers as $hInfo)
   {
    if (empty($hInfo))
     continue;
    if (strpos($hInfo, ': ') === false)
     continue;
    list($hKey, $hVal) = explode(': ', $hInfo, 2);
    $hdrs[strtolower($hKey)] = strtolower($hKey).':'.trim($hVal);
   }
   foreach ($aHOrder as $hID)
   {
    if (array_key_exists(strtolower($hID), $hdrs))
     $hRet.= $hdrs[strtolower($hID)]."\r\n";
    else
     $hRet.= strtolower($hID).":\r\n";
   }
   while (strpos($hRet, "\t") !== false)
    $hRet = str_replace("\t", " ", $hRet);
   while (strpos($hRet, "  ") !== false)
    $hRet = str_replace("  ", " ", $hRet);
   return $hRet;
  }
  foreach ($aHOrder as $hID)
  {
   if (strpos("\n".$headers, "\n".$hID) === false)
   {
    $hRet.= $hID.":\r\n";
    continue;
   }
   $findH = substr($headers, strpos("\n".$headers, "\n".$hID));
   if (strpos($findH, "\r\n") !== false)
   {
    $nextLn = 0;
    do
    {
     $nextLn = strpos($findH, "\r\n", $nextLn) + 2;
     $nextCh = substr($findH, $nextLn, 1);
     if ($nextCh === " " || $nextCh === "\t")
      continue;
     $findH = substr($findH, 0, $nextLn);
     break;
    } while($nextLn !== false);
   }
   $hRet.= $findH;
  }
  return $hRet;
 }

 function verify_dkim($dkimHeader, $headers_in, $message_in)
 {
  global $openssl_cmds, $message;
  global $tmp_dir;
  if (substr($tmp_dir, -1) !== '/')
   $tmp_dir .= '/';
  dkim_init();
  $dkimVals = array();
  if (strpos($dkimHeader, ';') !== false)
  {
   $dkimLine = explode(';', $dkimHeader);
   foreach ($dkimLine as $kv)
   {
    if (empty($kv))
     continue;
    if (strpos($kv, '=') === false)
     continue;
    list($lKey, $lVal) = explode('=', $kv, 2);
    $dkimVals[strtolower(str_replace(' ', '',$lKey))] = str_replace(' ',  '', $lVal);
   }
  }
  else
  {
   if (empty($dkimHeader))
    continue;
   if (strpos($dkimHeader, '=') === false)
    continue;
   list($lKey, $lVal) = explode('=', $dkimHeader, 2);
   $dkimVals[strtolower(str_replace(' ', '',$lKey))] = str_replace(' ',  '', $lVal);
  }
  $algos = 'rsa-sha256';
  if (array_key_exists('a', $dkimVals))
   $algos = $dkimVals['a'];
  $hAlgo = 'sha256';
  $sAlgo = 'rsa';
  if (strpos($algos, '-') === false)
   $sAlgo = $algos;
  else
   list($sAlgo, $hAlgo) = explode('-', $algos, 2);
  $domain = '';
  if (array_key_exists('d', $dkimVals))
   $domain = $dkimVals['d'];
  if (empty($domain))
   return 3;
  $selector = '';
  if (array_key_exists('s', $dkimVals))
   $selector = $dkimVals['s'];
  if (empty($selector))
   return 3;
  $canon = 'simple/simple';
  if (array_key_exists('c', $dkimVals))
   $canon = $dkimVals['c'];
  $hCanon = 'simple';
  $bCanon = 'simple';
  if (strpos($canon, '/') === false)
   $hCanon = $canon;
  else
   list($hCanon, $bCanon) = explode('/', $canon, 2);
  $timeS = 0;
  if (array_key_exists('t', $dkimVals))
   $timeS = $dkimVals['t'];
  if (!is_numeric($timeS))
   return 3;
  else
   $timeS = intval($timeS);
  $timeF = 0;
  if (array_key_exists('x', $dkimVals))
   $timeF = $dkimVals['x'];
  else
   $timeF = intval($timeF);
  if (!is_numeric($timeF))
   return 3;
  $headerOrder = 'From';
  if (array_key_exists('h', $dkimVals))
   $headerOrder = $dkimVals['h'];
  if (empty($headerOrder) || strpos(strtolower($headerOrder), 'from') === false)
   return 3;
  $hOrder = array();
  if (strpos($headerOrder, ':') === false)
   $hOrder[] = $headerOrder;
  else
   $hOrder = explode(':', $headerOrder);
  $bodyHash = '';
  if (array_key_exists('bh', $dkimVals))
   $bodyHash = $dkimVals['bh'];
  if (empty($bodyHash))
   return 3;
  $signature = '';
  if (array_key_exists('b', $dkimVals))
   $signature = $dkimVals['b'];
  if (empty($signature))
   return 3;
  $length = -1;
  if (array_key_exists('l', $dkimVals))
   $length = $dkimVals['l'];
  if (!is_numeric($length))
   return 3;
  if (strtolower($bCanon) === 'relaxed')
   $canonBody = dkim_canon_body('r', $message_in, $length);
  else
   $canonBody = dkim_canon_body('s', $message_in, $length);
  $calcHash = base64_encode(hash($hAlgo, $canonBody, true));
  if ($calcHash !== $bodyHash)
   return 4;
  if (strtolower($hCanon) === 'relaxed')
   $canonHeader = dkim_canon_header('r', $headers_in, $hOrder);
  else
   $canonHeader = dkim_canon_header('s', $headers_in, $hOrder);

  $pubKey = dkim_dns_record($selector.'._domainkey.'.$domain);
  if ($pubKey === false)
   return 7;

  $tmphdrs = tempnam($tmp_dir, 'hdr0');
  $fd = fopen($tmphdrs, "w");
  if ($fd)
  {
   $len = fwrite($fd, $canonHeader);
   fclose($fd);
   chmod($tmphdrs, 0600);
  }
  $tmpsig = tempnam($tmp_dir, 'sig0');
  $fd = fopen($tmpsig, "w");
  if ($fd)
  {
   $len = fwrite($fd, base64_decode($signature));
   fclose($fd);
   chmod($tmpsig, 0600);
  }
  $tmpcert = tempnam($tmp_dir, 'cert0');
  $fd = fopen($tmpcert, "w");
  if ($fd)
  {
   $len = fwrite($fd, $pubKey);
   fclose($fd);
   chmod($tmpcert, 0600);
  }
  exec("$openssl_cmds --verify-dkim-msg $hAlgo $tmphdrs $tmpcert $tmpsig 2>/dev/null", $message_out, $retval);
  unlink($tmphdrs);
  unlink($tmpcert);
  unlink($tmpsig);

  if ($retval != 1)
   return 5;
  if ($timeS > 0 && $timeS > time())
   return 2;
  if ($timeF > 0 && $timeF < time())
   return 2;
  if (intval($length) > -1)
   return 1;
  return 0;
 }

 function convert_dkim_verify_result_to_displayable_text($retval)
 {
  sq_change_text_domain('dkim');
  switch ($retval)
  {
   case 0: $str = _("Valid"); break;
   case 1: $str = _("Valid - Message is partially signed"); break;
   case 2: $str = _("Valid - Signature is expired"); break;
   case 3: $str = _("Invalid - Header is invalid"); break;
   case 4: $str = _("Invalid - Message has been altered"); break;
   case 5: $str = _("Invalid - Signature is invalid"); break;
   case 6: $str = _("Unverified"); break;
   case 7: $str = _("Unverified - DNS record unavailable"); break;
   case 8: $str = _("Invalid - Strict domain failure"); break;
   case 9: $str = _("Invalid - No compatible key type"); break;
   case 10: $str = _("Invalid - No compatible hash algorithm"); break;
  }
  sq_change_text_domain('squirrelmail');
  return $str;
 }

 function dkim_fetch_full_body ($imap_stream, $id)
 {
  $cmd = "FETCH $id BODY.PEEK[]";
  $data = sqimap_run_command($imap_stream, $cmd, true, $response, $message, true);
  $topline = array_shift($data);
  while (! preg_match('/\\* [0-9]+ FETCH /', $topline) && $data)
   $topline = array_shift($data);
  $wholemessage = implode('', $data);
  if (preg_match('/\\{([^\\}]*)\\}/', $topline, $regs))
   return substr($wholemessage, 0, $regs[1]);
  else if (preg_match('/"([^"]*)"/', $topline, $regs))
   return $regs[1];
  if (!empty($response) && $response !== 'OK')
   return "Error fetching message BODY: $response ($message)";
  return "Failed to fetch message BODY";
 }

 function dkim_header_data()
 {
  global $message;
  $hdrs = array();
  foreach ($message->rfc822_header->raw_headers as $hInfo)
  {
   if (empty($hInfo))
    continue;
   if (strpos($hInfo, ': ') === false)
    continue;
   list($hKey, $hVal) = explode(': ', $hInfo, 2);
   $hdrs[strtolower($hKey)] = $hVal;
  }
  return $hdrs;
 }

 function dkim_header_verify_do()
 {
  global $imapConnection, $passed_id, $color, $message,
         $mailbox, $where, $what, $startMessage,
         $row_highlite_color;
  $headerList = dkim_header_data();
  if (!array_key_exists('dkim-signature', $headerList))
   return;
  dkim_working_directory_init();
  $body = dkim_fetch_full_body($imapConnection, $passed_id);
  if (strpos($body, "\r\n\r\n") === false)
  {
   $retval = 6;
   $sign_result = "Error Reading Message: $body";
  }
  else
  {
   $hdrs = substr($body, 0, strpos($body, "\r\n\r\n") + 2);
   $body = substr($body, strpos($body, "\r\n\r\n") + 4);
   $retval = verify_dkim($headerList['dkim-signature'], $hdrs, $body);
   $sign_result = convert_dkim_verify_result_to_displayable_text($retval);
  }
  sq_change_text_domain('dkim');
  if ($retval < 3)
   $sign_verified = TRUE;
  else
   $sign_verified = FALSE;
  if (check_sm_version(1, 5, 2))
  {
   global $oTemplate;
   $oTemplate->assign('dkim_row_highlite_color', $row_highlite_color);
   $oTemplate->assign('dkim_sign_verified', $sign_verified);
   $oTemplate->assign('dkim_sign_result', $sign_result, FALSE);
   $output = $oTemplate->fetch('plugins/dkim/dkim.tpl');
   return array('read_body_header' => $output);
  }
  else
  {
   $colortag1 = '';
   $colortag2 = '';
   if (!$sign_verified)
   {
      $colortag1 = "<font color=\"$color[2]\"><b>";
      $colortag2 = '</b></font>';
   }
   echo "      <tr bgcolor=\"$row_highlite_color\">\n"
      . "        <td width=\"20%\" align=\"right\" valign=\"top\">\n<b>"
      . _("DKIM")
      . "        </b></td><td width=\"80%\" align=\"left\" valign=\"top\">\n"
      . "          $colortag1 $sign_result$colortag2\n"
      . "        </td>\n"
      . "      </tr>\n";
  }
  sq_change_text_domain('squirrelmail');
 }

 function dkim_working_directory_init()
 {
  global $tmp_dir;
  dkim_init();
  $oldmask = umask(077);
  if (!is_dir($tmp_dir))
   mkdir($tmp_dir, 01700);
  umask($oldmask);
 }
