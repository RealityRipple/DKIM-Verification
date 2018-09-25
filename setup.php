<?php
 function squirrelmail_plugin_init_dkim() 
 {
  global $squirrelmail_plugin_hooks;
  $squirrelmail_plugin_hooks['read_body_header']['dkim'] = 'dkim_header_verify';
  $squirrelmail_plugin_hooks['template_construct_read_headers.tpl']['dkim'] = 'dkim_header_verify';
  $squirrelmail_plugin_hooks['configtest']['dkim'] = 'dkim_check_configuration';
 }
 function dkim_header_verify() 
 {
  include_once(SM_PATH . 'plugins/dkim/functions.php');
  return dkim_header_verify_do();
 }
 function dkim_check_configuration()
 {
  include_once(SM_PATH . 'plugins/dkim/functions.php');
  return dkim_check_configuration_do();
 }
 function dkim_info() 
 {
  return array(
   'english_name' => 'DKIM Verification',
   'authors' => array(
    'Andrew Sachen' => array(
     'email' => 'webmaster@realityripple.com',
    )
   ),
   'version' => '0.1',
   'required_sm_version' => '1.1.1',
   'requires_configuration' => 0,
   'summary' => 'Verifies DKIM signed messages.',
   'details' => 'This plugin quickly displays the validity of DKIM signed messages (those that are sent with a "DKIM-Signature" header).',
   'requires_source_patch' => 0,
   'other_requirements' => 'openssl',
   'per_version_requirements' => array(
    '1.5.2' => array(
     'required_plugins' => array(),
    ),
    '1.5.0' => array(
     'required_plugins' => array(
      'compatibility' => array(
       'version' => '2.0.7',
       'activate' => FALSE,
      )
     )
    ),
    '1.4.10' => array(
     'required_plugins' => array(),
    ),
    '1.4.0' => array(
     'required_plugins' => array(
      'compatibility' => array(
       'version' => '2.0.7',
       'activate' => FALSE,
      )
     )
    ),
   ),
  );
 }
 function dkim_version() 
 {
  $info = dkim_info();
  return $info['version'];
 }
