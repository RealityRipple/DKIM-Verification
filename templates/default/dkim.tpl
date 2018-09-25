<?php extract($t); ?>
<tr id="dkim" bgcolor="<?php echo $dkim_row_highlite_color; ?>">
  <td class="fieldName">
    <b><?php echo _("DKIM"); ?>:</b>
  </td>
  <td class="<?php if ($dkim_sign_verified) echo 'fieldValue'; else echo 'error_header'; ?>">
    <?php echo $dkim_sign_result; ?>
  </td>
</tr>
