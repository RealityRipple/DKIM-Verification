<?php
 global $color, $row_highlite_color;
 global $openssl_cmds, $tmp_dir;

 // This is the color used in the background of the signature
 // verification information presented to the user.  $color[9]
 // may be subdued in some display themes, $color[16] will usually
 // stand out rather strongly.  You may add any color you would
 // like here, including static ones.  This information may or may
 // not be used under SquirrelMail 1.5.2+.
 //
 // $row_highlite_color = $color[9];
 // $row_highlite_color = $color[16];
 // $row_highlite_color = '#ff9933';
 //
 $row_highlite_color = $color[16];

 // This is the full path to the OpenSSL cmds shell script.
 //
 $openssl_cmds = '/usr/share/squirrelmail/plugins/dkim/openssl-cmds.sh';

 // This is the directory where temporary files are stored.
 // It must be readable and writeable by the user your web server runs as.
 // This setting's default value usually does not need to be changed.
 //
 $tmp_dir = '/tmp/';
?>
