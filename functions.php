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

 function dkim_dns_clean_ret($ret)
 {
  if (strpos($ret, '"') === false && strpos($ret, '\\') === false)
   return $ret;
  $ret = str_replace('\\;', ';', $ret);
  $ret = str_replace('" "', '', $ret);
  return str_replace('"', '', $ret);
 }

 function dkim_dns_get_txt($domain)
 {
  $out = null;
  $ret = null;
  exec("dig -t txt +short $domain", $out, $ret);
  if ($ret !== 0)
   return false;
  if (count($out) === 0)
   return false;
  $fRet = array();
  foreach ($out as $rL)
  {
   $fRet[] = dkim_dns_clean_ret($rL);
  }
  return $fRet;
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

 function dkim_dns_policy($host)
 {
  $ret = dkim_dns_get_txt($host, DNS_TXT);
  if ($ret === false)
   return false;
  if (count($ret) < 1)
   return false;
  $results = array();
  foreach ($ret as $record)
  {
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
     $lKey = strtolower(str_replace(' ', '',$lKey));
     $lVal = str_replace(' ',  '', $lVal);
     if (!array_key_exists($lKey, $recVals))
      $recVals[$lKey] = array();
     $recVals[$lKey][] = $lVal;
    }
   }
   else
   {
    if (empty($record))
     continue;
    if (strpos($record, '=') === false)
     continue;
    list($lKey, $lVal) = explode('=', $record, 2);
    $lKey = strtolower(str_replace(' ', '',$lKey));
    $lVal = str_replace(' ',  '', $lVal);
    if (!array_key_exists($lKey, $recVals))
     $recVals[$lKey] = array();
    $recVals[$lKey][] = $lVal;
   }
   if (!array_key_exists('o', $recVals))
    continue;
   foreach ($recVals['o'] as $recSvc)
   {
    if (strpos($recSvc, ':') === false)
     $results[] = $recSvc;
    else
     array_push($results, explode(':', $recSvc));
   }
  }
  if (count($results) > 0)
  {
   foreach ($results as $ret)
   {
    if ($ret === '.')
     return '.';
   }
   foreach ($results as $ret)
   {
    if ($ret === '!')
     return '!';
   }
   foreach ($results as $ret)
   {
    if ($ret === '-')
     return '-';
   }
  }
  return '~';
 }

 function dkim_dns_record($host, &$acceptedHashes, &$strict)
 {
  $noKey = false;
  $acceptedHashes = null;
  $strict = false;
  $ret = dkim_dns_get_txt($host, DNS_TXT);
  if ($ret === false)
   return false;
  if (count($ret) < 1)
   return false;
  $pubKeys = array();
  foreach ($ret as $record)
  {
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
     $lKey = strtolower(str_replace(' ', '',$lKey));
     $lVal = str_replace(' ',  '', $lVal);
     if (!array_key_exists($lKey, $recVals))
      $recVals[$lKey] = array();
     $recVals[$lKey][] = $lVal;
    }
   }
   else
   {
    if (empty($record))
     continue;
    if (strpos($record, '=') === false)
     continue;
    list($lKey, $lVal) = explode('=', $record, 2);
    $lKey = strtolower(str_replace(' ', '',$lKey));
    $lVal = str_replace(' ',  '', $lVal);
    if (!array_key_exists($lKey, $recVals))
     $recVals[$lKey] = array();
    $recVals[$lKey][] = $lVal;
   }
   if (!array_key_exists('p', $recVals))
    continue;
   if (array_key_exists('v', $recVals) && !in_array('DKIM1', $recVals['v']))
    continue;
   if (array_key_exists('s', $recVals))
   {
    $services = array();
    foreach ($recVals['s'] as $recSvc)
    {
     if (strpos($recSvc, ':') === false)
      $services[] = $recSvc;
     else
      array_push($services, explode(':', $recSvc));
    }
    if (!in_array('*', $services) && !in_array('email', $services))
     continue;
   }
   if (array_key_exists('k', $recVals))
   {
    if (!in_array('rsa', $recVals['k']) && !in_array('dsa', $recVals['k']) && !in_array('ecdsa256', $recVals['k']) && !in_array('ecdsa384', $recVals['k']) && !in_array('ecdsa521', $recVals['k']))
    {
     $noKey = true;
     continue;
    }
   }
   if (array_key_exists('h', $recVals))
   {
    $hashTypes = array();
    foreach ($recVals['h'] as $recHash)
    {
     if (strpos($recHash, ':') === false)
      $hashTypes[] = $recHash;
     else
      array_push($hashTypes, explode(':', $recHash));
    }
    $acceptedHashes = $hashTypes;
   }
   if (array_key_exists('t', $recVals))
   {
    $flags = array();
    foreach ($recVals['t'] as $recFlag)
    {
     if (strpos($recFlag, ':') === false)
      $flags[] = $recFlag;
     else
      array_push($flags, explode(':', $recFlag));
    }
    if (in_array('s', $flags))
     $strict = true;
   }
   foreach ($recVals['p'] as $recKey)
   {
    $recKey = wordwrap($recKey, 64, "\r\n", true);
    $pubKeys[] = "-----BEGIN PUBLIC KEY-----\r\n$recKey\r\n-----END PUBLIC KEY-----\r\n";
   }
  }
  if (count($pubKeys) > 0)
   return $pubKeys;
  if ($noKey)
   return 0;
  return false;
 }

 function dkim_canon_body($canon, $body, $length)
 {
  if ($canon === 'r')
  {
   while (strpos($body, "\t") !== false)
    $body = str_replace("\t", " ", $body);
   while (strpos($body, "  ") !== false)
    $body = str_replace("  ", " ", $body);
   while (strpos($body, " \r\n") !== false)
    $body = str_replace(" \r\n", "\r\n", $body);
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

 function verify_dkim($dkimHeader, $headers_in, $message_in, &$signerDomain)
 {
  global $openssl_cmds, $message;
  global $tmp_dir;
  $signerDomain = null;
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
    return 0x1001;
   if (strpos($dkimHeader, '=') === false)
    return 0x1001;
   list($lKey, $lVal) = explode('=', $dkimHeader, 2);
   $dkimVals[strtolower(str_replace(' ', '',$lKey))] = str_replace(' ',  '', $lVal);
  }
  $domain = '';
  if (array_key_exists('d', $dkimVals))
   $domain = $dkimVals['d'];
  if (empty($domain))
   return 0x1001;
  $signerDomain = $domain;
  $algos = 'rsa-sha256';
  if (array_key_exists('a', $dkimVals))
   $algos = $dkimVals['a'];
  $hAlgo = 'sha256';
  $sAlgo = 'rsa';
  if (strpos($algos, '-') === false)
   $hAlgo = $algos;
  else
   list($sAlgo, $hAlgo) = explode('-', $algos, 2);
  $selector = '';
  if (array_key_exists('s', $dkimVals))
   $selector = $dkimVals['s'];
  if (empty($selector))
   return 0x1001;
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
   return 0x1001;
  else
   $timeS = intval($timeS);
  $timeF = 0;
  if (array_key_exists('x', $dkimVals))
   $timeF = $dkimVals['x'];
  else
   $timeF = intval($timeF);
  if (!is_numeric($timeF))
   return 0x1001;
  $headerOrder = 'From';
  if (array_key_exists('h', $dkimVals))
   $headerOrder = $dkimVals['h'];
  if (empty($headerOrder) || strpos(strtolower($headerOrder), 'from') === false)
   return 0x1001;
  $hOrder = array();
  if (strpos($headerOrder, ':') === false)
   $hOrder[] = $headerOrder;
  else
   $hOrder = explode(':', $headerOrder);
  $bodyHash = '';
  if (array_key_exists('bh', $dkimVals))
   $bodyHash = $dkimVals['bh'];
  if (empty($bodyHash))
   return 0x1001;
  $signature = '';
  if (array_key_exists('b', $dkimVals))
   $signature = $dkimVals['b'];
  if (empty($signature))
   return 0x1001;
  $length = -1;
  if (array_key_exists('l', $dkimVals))
   $length = $dkimVals['l'];
  if (!is_numeric($length))
   return 0x1001;
  if (strtolower($bCanon) === 'relaxed')
   $canonBody = dkim_canon_body('r', $message_in, $length);
  else
   $canonBody = dkim_canon_body('s', $message_in, $length);
  $calcHash = base64_encode(hash($hAlgo, $canonBody, true));
  if ($calcHash !== $bodyHash)
   return 0x2001;
  if (strtolower($hCanon) === 'relaxed')
   $canonHeader = dkim_canon_header('r', $headers_in, $hOrder);
  else
   $canonHeader = dkim_canon_header('s', $headers_in, $hOrder);
  $dkimStrict = false;
  $dkimAlgos = null;
  $pubKeys = dkim_dns_record($selector.'._domainkey.'.$domain, $dkimAlgos, $dkimStrict);
  if ($pubKeys === false)
   return 0x102;
  if ($pubKeys === 0)
   return 0x10001;
  if ($dkimAlgos !== null)
  {
   if (!in_array(strtolower($hAlgo), $dkimAlgos))
    return 0x20001;
  }
  if (array_key_exists('i', $dkimVals))
  {
   $iDomain = $dkimVals['i'];
   if (strpos($iDomain, '@') !== false)
    $iDomain = substr($iDomain, strrpos($iDomain, '@') + 1);
   if ($dkimStrict)
   {
    if (strtolower($iDomain) !== strtolower($domain))
     return 0x8001;
   }
   else if (strtolower(substr($iDomain, -1 * strlen($domain))) !== strtolower($domain))
    return 0x8001;
  }
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
  $retval = 0;
  foreach ($pubKeys as $pubKey)
  {
   $tmpcert = tempnam($tmp_dir, 'cert0');
   $fd = fopen($tmpcert, "w");
   if ($fd)
   {
    $len = fwrite($fd, $pubKey);
    fclose($fd);
    chmod($tmpcert, 0600);
   }
   exec("$openssl_cmds --verify-dkim-msg $hAlgo $tmphdrs $tmpcert $tmpsig 2>/dev/null", $message_out, $retval);
   unlink($tmpcert);
   if ($retval == 1)
    break;
  }
  unlink($tmphdrs);
  unlink($tmpsig);
  if ($retval != 1)
   return 0x4001;
  if ($timeS > 0 && $timeS > time())
   return 0x20;
  if ($timeF > 0 && $timeF < time())
   return 0x20;
  if (intval($length) > -1)
   return 0x10;
  return 0x00;
 }

 function convert_dkim_verify_result_to_displayable_text($retval)
 {
  sq_change_text_domain('dkim');
  $str = '';
  if (($retval & 0x01) == 0x01)
   $str = _("Invalid");
  else if (($retval & 0x02) == 0x02)
   $str = _("Unverified");
  else if (($retval & 0x04) == 0x04)
   $str = _("Invalid");
  else if (($retval & 0x08) == 0x08)
   $str = _("Invalid");
  else
   $str = _("Valid");
  if (($retval & 0x10) == 0x10)
   $str.= _(" - ")._("Message is partially signed");
  if (($retval & 0x20) == 0x20)
   $str.= _(" - ")._("Signature is expired");
  if (($retval & 0x100) == 0x100)
   $str.= _(" - ")._("DNS record unavailable");
  if (($retval & 0x1000) == 0x1000)
   $str.= _(" - ")._("Header is invalid");
  if (($retval & 0x2000) == 0x2000)
   $str.= _(" - ")._("Message has been altered");
  if (($retval & 0x4000) == 0x4000)
   $str.= _(" - ")._("Signature is invalid");
  if (($retval & 0x8000) == 0x8000)
   $str.= _(" - ")._("Different domain");
  if (($retval & 0x10000) == 0x10000)
   $str.= _(" - ")._("No compatible key type");
  if (($retval & 0x20000) == 0x20000)
   $str.= _(" - ")._("No compatible hash algorithm");
  if (($retval & 0x100000) == 0x100000)
   $str.= _(" - ")._("Domain does not send mail");
  if (($retval & 0x200000) == 0x200000)
   $str.= _(" - ")._("Domain requires signature");
  if (($retval & 0x400000) == 0x400000)
   $str.= _(" - ")._("Signed by third-party");
  
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
   $hKey = strtolower(str_replace(' ', '',$hKey));
   $hVal = str_replace(' ',  '', $hVal);
   if (!array_key_exists($hKey, $hdrs))
    $hdrs[$hKey] = array();
   $hdrs[$hKey][] = $hVal;
  }
  return $hdrs;
 }

 function dkim_display($domain, $retval, $retstr = null)
 {
  global $row_highlite_color;
  sq_change_text_domain('dkim');
  if (($retval & 0x0F) == 0)
   $sign_verified = true;
  else
   $sign_verified = false;
  if ($retstr === null)
   $retstr = convert_dkim_verify_result_to_displayable_text($retval);
  if (check_sm_version(1, 5, 2))
  {
   global $oTemplate;
   $oTemplate->assign('dkim_row_highlite_color', $row_highlite_color);
   $oTemplate->assign('dkim_sign_domain', $domain);
   $oTemplate->assign('dkim_sign_verified', $sign_verified);
   $oTemplate->assign('dkim_sign_result', $retstr, FALSE);
   $output = $oTemplate->fetch('plugins/dkim/dkim.tpl');
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
   $output = "      <tr bgcolor=\"$row_highlite_color\">\n"
           . "        <td width=\"20%\" align=\"right\" valign=\"top\">\n<b>"
           . $domain . _(" DKIM")
           . "        </b></td><td width=\"80%\" align=\"left\" valign=\"top\">\n"
           . "          $colortag1 $retstr$colortag2\n"
           . "        </td>\n"
           . "      </tr>\n";
  }
  sq_change_text_domain('squirrelmail');
  return $output;
 }

 function dkim_header_verify_do()
 {
  global $imapConnection, $passed_id, $color, $message,
         $mailbox, $where, $what, $startMessage,
         $row_highlite_color;
  $headerList = dkim_header_data();
  $fromList = array();
  $dnsPols = array();
  $output = '';
  if (array_key_exists('from', $headerList))
  {
   foreach ($headerList['from'] as $fromAddr)
   {
    if (empty($fromAddr))
     continue;
    if (strpos($fromAddr, '@') === false)
     continue;
    $fDomain = substr($fromAddr, strpos($fromAddr, '@') + 1);
    $fromList[] = strtolower($fDomain);
    $dPol = dkim_dns_policy('_domainkey.'.$fDomain);
    $dnsPols[strtolower($fDomain)] = $dPol;
    if ($dPol === '.')
     $output.= dkim_display($fDomain, 0x100001);
   }
  }
  if (!array_key_exists('dkim-signature', $headerList))
  {
   if (count($dnsPols) > 0)
   {
    foreach ($dnsPols as $dPol)
    {
     if ($dPol === '-' || $dPol === '!')
     {
      $output.= dkim_display($fDomain, 0x200001);
      break;
     }
    }
   }
  }
  else
  {
   dkim_working_directory_init();
   $body = dkim_fetch_full_body($imapConnection, $passed_id);
   foreach ($headerList['dkim-signature'] as $headerSig)
   {
    $signerDomain = null;
    if (strpos($body, "\r\n\r\n") === false)
    {
     $retval = 6;
     $sign_result = "Error Reading Message: $body";
     $output.= dkim_display('', $retval, $sign_result);
    }
    else
    {
     $hdrs = substr($body, 0, strpos($body, "\r\n\r\n") + 2);
     $bOut = substr($body, strpos($body, "\r\n\r\n") + 4);
     $retval = verify_dkim($headerSig, $hdrs, $bOut, $signerDomain);
     if (!array_key_exists(strtolower($signerDomain), $dnsPols))
     {
      $dPol = dkim_dns_policy('_domainkey.'.$signerDomain);
      $dnsPols[strtolower($signerDomain)] = $dPol;
     }
     else
      $dPol = $dnsPols[strtolower($signerDomain)];
     if ($dPol === '!')
     {
      if (($retval & 0x0F) > 0)
       $retval |= 0x200000;
      else if (!in_array(strtolower($signerDomain), $fromList))
       $retval |= 0x400000;
     }
     else if ($dPol === '.')
     {
      if (($retval & 0x0F) > 0)
       $retval |= 0x200000;
     }
     $output.= dkim_display($signerDomain, $retval);
    }
   }
  }
  if ($output !== '')
  {
   if (check_sm_version(1, 5, 2))
    return array('read_body_header' => $output);
   echo $output;
  }
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
