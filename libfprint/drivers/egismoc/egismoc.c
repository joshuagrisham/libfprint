/*
 * Driver for Egis Technology (LighTuning) Match-On-Chip sensors
 * Originally authored 2023 by Joshua Grisham <josh@joshuagrisham.com>
 *
 * Portions of code and logic inspired from the elanmoc libfprint driver 
 * which is copyright (C) 2021 Elan Microelectronics Inc (see elanmoc.c)
 *
 * Based on original reverse-engineering work by Joshua Grisham. The protocol has
 * been reverse-engineered from captures of the official Windows driver, and by
 * testing commands on the sensor with a multiplatform Python prototype driver:
 * https://github.com/joshuagrisham/galaxy-book2-pro-linux/tree/main/fingerprint/
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "egismoc"

#include <stdio.h>
#include <glib.h>
#include <sys/param.h>

#include "drivers_api.h"

#include "egismoc.h"

G_DEFINE_TYPE (FpiDeviceEgisMoc, fpi_device_egismoc, FP_TYPE_DEVICE);

static const FpIdEntry egismoc_id_table[] = {
  { .vid = 0x1c7a, .pid = 0x0582 },
  { .vid = 0,      .pid = 0 }
};

typedef void (*SynCmdMsgCallback) (FpDevice *device,
                                   guchar   *buffer_in,
                                   gsize     length_in,
                                   GError   *error);

typedef struct egismoc_command_data
{
  EgisMocCommand    *cmd;
  SynCmdMsgCallback  callback;
} CommandData;

typedef struct egismoc_enroll_print
{
  FpPrint *print;
  int      stage;
} EnrollPrint;

static void
egismoc_finger_on_sensor_cb (FpiUsbTransfer *transfer,
                             FpDevice       *device,
                             gpointer        userdata,
                             GError         *error)
{
  fp_dbg ("Finger on sensor callback");
  fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);

  g_return_if_fail (transfer->ssm);
  if (error)
    fpi_ssm_mark_failed (transfer->ssm, error);
  else
    fpi_ssm_next_state (transfer->ssm);
}

static void
egismoc_wait_finger_on_sensor (FpiSsm   *ssm,
                               FpDevice *device)
{
  fp_dbg ("Wait for finger on sensor");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (device);

  fpi_usb_transfer_fill_interrupt (transfer, EGISMOC_EP_CMD_INTERRUPT_IN, EGISMOC_USB_INTERRUPT_IN_RECV_LENGTH);
  transfer->ssm = ssm;
  transfer->short_is_error = FALSE; /* Interrupt on this device always returns 1 byte short; this is expected */

  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);

  fpi_usb_transfer_submit (g_steal_pointer (&transfer),
                           EGISMOC_USB_INTERRUPT_TIMEOUT,
                           self->interrupt_cancellable,
                           egismoc_finger_on_sensor_cb,
                           NULL);
}

static gboolean
egismoc_validate_response_prefix (const guchar *buffer_in,
                                  const size_t  buffer_in_len,
                                  const guchar *valid_prefix,
                                  const size_t  valid_prefix_len)
{
  const gboolean result = memcmp (buffer_in + (egismoc_read_prefix_len + EGISMOC_CHECK_BYTES_LENGTH),
                                  valid_prefix,
                                  valid_prefix_len) == 0;
  fp_dbg ("Response prefix valid: %s", result ? "yes" : "NO");
  return result;
}

static gboolean
egismoc_validate_response_suffix (const guchar *buffer_in,
                                  const size_t  buffer_in_len,
                                  const guchar *valid_suffix,
                                  const size_t  valid_suffix_len)
{
  const gboolean result = memcmp (buffer_in + (buffer_in_len - valid_suffix_len),
                                  valid_suffix,
                                  valid_suffix_len) == 0;
  fp_dbg ("Response suffix valid: %s", result ? "yes" : "NO");
  return result;
}

static void
egismoc_task_ssm_done (FpiSsm   *ssm,
                       FpDevice *device,
                       GError   *error)
{
  fp_dbg ("Task SSM done");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  self->task_ssm = NULL;
  self->enrolled_ids = NULL;

  if (error)
    fpi_device_action_error (device, error);
}

static void
egismoc_task_ssm_next_state_cb (FpDevice *device,
                                guchar   *buffer_in,
                                gsize     length_in,
                                GError   *error)
{
  fp_dbg ("Task SSM next state callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  if (error)
    fpi_ssm_mark_failed (self->task_ssm, error);
  else
    fpi_ssm_next_state (self->task_ssm);
}

/*
  Derive the 2 "check bytes" for write payloads
  32-bit big-endian sum of all 16-bit words (including check bytes) MOD 0xFFFF should be 0, otherwise
  the device will reject the payload
*/
static guchar *
egismoc_get_check_bytes (const guchar *value,
                         const size_t  value_length,
                         const size_t  check_bytes_length)
{
  fp_dbg ("Get check bytes");
  guchar *check_bytes = g_malloc0 (check_bytes_length);
  unsigned short check_short;
  guchar *check_short_split;

  unsigned short value_bigendian_shorts[(int)((value_length + 1) / 2)];

  int s = 0;
  for (int i=0; i<value_length; i=i+2)
    {
      if (i+1 < value_length)
        value_bigendian_shorts[s] = (((short)value[i+1]) << 8) | (0x00ff & value[i]);
      else
        value_bigendian_shorts[s] = (((short)0x00) << 8) | (0x00ff & value[i]);
      s++;
    }
  unsigned long sum_shorts = 0;
  for (int i=0; i<s; i++)
    sum_shorts += value_bigendian_shorts[i];

  /* 
    derive the "first possible occurence" of check bytes as:
    `0xFFFF - (sum_of_32bit_words % 0xFFFF)
  */
  check_short = 0xffff - (sum_shorts % 0xffff);

  /* split the short into chars and then fill check bytes with them */
  check_short_split = (guchar*)&check_short;
  for (int i=0; i<check_bytes_length; i++)
    check_bytes[i] = check_short_split[i];

  return g_steal_pointer (&check_bytes);
}

/*
  This method will create a "full" payload which looks like this:
    E G I S 00 00 00 01 {cb1} {cb2} {payload}
  where cb1 and cb2 are some check bytes generated by the egismoc_get_check_bytes
  method and payload is what is passed via the parameter
*/
static EgisMocCommand *
egismoc_compose_cmd (const guchar *cmd,
                     const size_t  cmd_length)
{
  fp_dbg ("Compose command");
  g_autofree guchar *check_bytes = NULL;
  const size_t total_length = egismoc_write_prefix_len
                              + EGISMOC_CHECK_BYTES_LENGTH
                              + cmd_length;
  guchar *result = g_malloc0 (total_length);
  EgisMocCommand *result_cmd = g_new0 (EgisMocCommand, 1);

  /* Now build the entire payload array */

  /* Prefix */
  memcpy (result, egismoc_write_prefix, egismoc_write_prefix_len);

  /* Check Bytes - leave them as 00 for now then later generate and copy over the real ones */

  /* Command Payload */
  memcpy (result + egismoc_write_prefix_len + EGISMOC_CHECK_BYTES_LENGTH, cmd, cmd_length);

  /* Now fetch and set the "real" check bytes based on the currently assembled payload */
  check_bytes = egismoc_get_check_bytes (result, total_length, EGISMOC_CHECK_BYTES_LENGTH);
  memcpy (result + egismoc_write_prefix_len, check_bytes, EGISMOC_CHECK_BYTES_LENGTH);

  /* Set up and return the final EgisMocCommand to be sent */
  result_cmd->cmd = result;
  result_cmd->cmd_length = total_length;
  return g_steal_pointer (&result_cmd);
}

static void
egismoc_cmd_receive_cb (FpiUsbTransfer *transfer,
                        FpDevice       *device,
                        gpointer        userdata,
                        GError         *error)
{
  fp_dbg ("Command receive callback");
  CommandData *data = userdata;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if (data == NULL || transfer->actual_length < egismoc_read_prefix_len)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  if (data->callback)
    data->callback (device, transfer->buffer, transfer->actual_length, NULL);

  fpi_ssm_mark_completed (transfer->ssm);
}

static void
egismoc_cmd_run_state (FpiSsm   *ssm,
                       FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autoptr(FpiUsbTransfer) transfer = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CMD_SEND:
      if (self->cmd_transfer)
        {
          self->cmd_transfer->ssm = ssm;
          fpi_usb_transfer_submit (g_steal_pointer (&self->cmd_transfer),
                                   EGISMOC_USB_SEND_TIMEOUT,
                                   NULL,
                                   fpi_ssm_usb_transfer_cb,
                                   NULL);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      break;
    case CMD_GET:
      transfer = fpi_usb_transfer_new (device);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_bulk (transfer, EGISMOC_EP_CMD_IN, EGISMOC_USB_IN_RECV_LENGTH);
      fpi_usb_transfer_submit (g_steal_pointer (&transfer),
                               EGISMOC_USB_RECV_TIMEOUT,
                               NULL,
                               egismoc_cmd_receive_cb,
                               fpi_ssm_get_data (ssm));
      break;
    }
}

static void
egismoc_cmd_ssm_done (FpiSsm   *ssm,
                      FpDevice *device,
                      GError   *error)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  CommandData *data = fpi_ssm_get_data (ssm);

  self->cmd_ssm = NULL;
  self->cmd_transfer = NULL;

  if (error)
    {
      if (data->callback)
        data->callback (device, NULL, 0, error);
      else
        g_error_free (error);
    }
}

static void
egismoc_get_cmd (FpDevice          *device,
                 EgisMocCommand    *cmd,
                 SynCmdMsgCallback  callback)
{
  fp_dbg ("Execute command and get response");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  g_autoptr(FpiUsbTransfer) transfer = NULL;
  CommandData *data = g_new0 (CommandData, 1);

  self->cmd_ssm = fpi_ssm_new (FP_DEVICE (self),
                               egismoc_cmd_run_state,
                               CMD_STATES);

  transfer = fpi_usb_transfer_new (device);
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (transfer, EGISMOC_EP_CMD_OUT, cmd->cmd,
                                   cmd->cmd_length, g_free);
  transfer->ssm = self->cmd_ssm;
  self->cmd_transfer = g_steal_pointer (&transfer);
  data->callback = callback;
  data->cmd = g_steal_pointer (&cmd);

  fpi_ssm_set_data (self->cmd_ssm, data, g_free);
  fpi_ssm_start (self->cmd_ssm, egismoc_cmd_ssm_done);
}

static void
egismoc_set_print_data (FpPrint      *print,
                        const guchar *device_print_id)
{
  g_autofree gchar *user_id = g_malloc (EGISMOC_FINGERPRINT_DATA_SIZE);
  memcpy (user_id, device_print_id, EGISMOC_FINGERPRINT_DATA_SIZE);

  fpi_print_fill_from_user_id (print, user_id);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);

  if (g_str_has_prefix (user_id, "FP"))
    g_object_set (print, "description", user_id, NULL);
  else
    {
      /* Give a "nice" description for non-libfprint prints instead of a non-printable byte string */
      gchar description_non_fprint[] = "Unknown (not created by libfprint) 00000000";
      size_t description_prefix_len = strlen ("Unknown (not created by libfprint) ");
      gchar tmp[3];
      for (int i=0; i<4; i++)
        {
          sprintf (tmp, "%02x", device_print_id[i]);
          description_non_fprint[description_prefix_len + i*2] = tmp[0];
          description_non_fprint[description_prefix_len + i*2 + 1] = tmp[1];
        }
      g_object_set (print, "description", description_non_fprint, NULL);
    }

  GVariant *print_id_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                      device_print_id,
                                                      EGISMOC_FINGERPRINT_DATA_SIZE,
                                                      sizeof (guchar));
  GVariant *fpi_data = g_variant_new ("(@ay)", print_id_var);
  g_object_set (print, "fpi-data", fpi_data, NULL);
}

static GPtrArray *
egismoc_get_enrolled_prints (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autoptr(GPtrArray) result = g_ptr_array_new_with_free_func (g_object_unref);
  guchar *device_print_id = NULL;
  FpPrint *print = NULL;

  for (int i = 0; i < self->enrolled_num; i++)
    {
      device_print_id = g_malloc0 (EGISMOC_FINGERPRINT_DATA_SIZE);
      device_print_id = g_ptr_array_index (self->enrolled_ids, i);
      print = fp_print_new (device);
      egismoc_set_print_data (print, device_print_id);
      g_ptr_array_add (result, g_object_ref_sink (print));
    }
  
  return g_steal_pointer (&result);
}

static void
egismoc_list_cb (FpDevice *device,
                 guchar   *buffer_in,
                 gsize     length_in,
                 GError   *error)
{
  fp_dbg ("List callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  guchar *print_id = NULL;
  int print_id_pos;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /*
    Each fingerprint ID will be returned in this response as a 32 byte array
    The other stuff in the payload is 16 bytes long, so if there is at least 1 print
    then the length should be at least 16+32=48 bytes long
  */
  if (length_in < (16 + EGISMOC_FINGERPRINT_DATA_SIZE))
    self->enrolled_num = 0;
  else
    {
      self->enrolled_num = (length_in - 16) / EGISMOC_FINGERPRINT_DATA_SIZE;
      for (int print_num=0; print_num<self->enrolled_num; print_num++)
        {
          print_id = g_malloc0 (EGISMOC_FINGERPRINT_DATA_SIZE);
          print_id_pos = 0;
          for (int buffer_in_pos=(14 + (print_num * EGISMOC_FINGERPRINT_DATA_SIZE));
               buffer_in_pos<(14 + (print_num * EGISMOC_FINGERPRINT_DATA_SIZE) + EGISMOC_FINGERPRINT_DATA_SIZE);
               buffer_in_pos++)
            {
              print_id[print_id_pos] = buffer_in[buffer_in_pos];
              print_id_pos++;
            }
          fp_dbg ("Device fingerprint %0d: %s", print_num, print_id);
          g_ptr_array_add (self->enrolled_ids, (gpointer) print_id);
        }
    }

  fp_info ("Number of currently enrolled fingerprints on the device is %d", self->enrolled_num);

  if (self->task_ssm)
    fpi_ssm_next_state (self->task_ssm);
}

static void
egismoc_fill_enrolled_ids (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  EgisMocCommand *cmd = NULL;

  self->enrolled_ids = g_ptr_array_new_with_free_func (g_object_unref);
  cmd = egismoc_compose_cmd (cmd_list, cmd_list_len);
  egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_list_cb);
}

static void
egismoc_list_run_state (FpiSsm   *ssm,
                        FpDevice *device)
{
  g_autoptr(GPtrArray) enrolled_prints = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case LIST_GET_ENROLLED_IDS:
      egismoc_fill_enrolled_ids (device);
      break;
    case LIST_RETURN_ENROLLED_PRINTS:
      enrolled_prints = egismoc_get_enrolled_prints (device);
      fpi_device_list_complete (device, g_steal_pointer (&enrolled_prints), NULL);
      fpi_ssm_next_state (ssm);
      break;
    }
}

static void
egismoc_list (FpDevice *device)
{
  fp_dbg ("List");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  self->task_ssm = fpi_ssm_new (device,
                                egismoc_list_run_state,
                                LIST_STATES);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static EgisMocCommand *
egismoc_get_delete_cmd (FpDevice *device,
                        FpPrint  *delete_print)
{
  fp_dbg ("Get delete command");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  const gchar *print_description;
  g_autoptr(GVariant) print_data = NULL;
  g_autoptr(GVariant) print_data_id_var = NULL;
  const guchar *print_data_id = NULL;
  gsize print_data_id_len = 0;
  g_autofree guchar *enrolled_print_id = NULL;
  guchar *result = NULL;
  EgisMocCommand *result_cmd = g_new0 (EgisMocCommand, 1);

  size_t pos = 0;

  /*
    The final command body should contain:
    1) hard-coded 00 00
    2) 2-byte size indiciator, 20*Number deleted identifiers plus 7 in form of: num_to_delete * 0x20 + 0x07
       Since max prints can be higher than 7 then this goes up to 2 bytes (e9 + 9 = 109)
    3) Hard-coded prefix (cmd_delete_prefix)
    4) 2-byte size indiciator, 20*Number of enrolled identifiers without plus 7 (num_to_delete * 0x20)
    5) All of the currently registered prints to delete in their 32-byte device identifiers (enrolled_list)
  */

  const int num_to_delete = (!delete_print) ? self->enrolled_num : 1;
  const size_t body_length = sizeof (guchar) * EGISMOC_FINGERPRINT_DATA_SIZE * num_to_delete;
  const size_t print_id_length = sizeof (guchar) * EGISMOC_FINGERPRINT_DATA_SIZE;
  /* total_length is the 6 various bytes plus prefix and body payload */
  const size_t total_length = (sizeof (guchar) * 6) + cmd_delete_prefix_len + body_length;

  /* pre-fill entire payload with 00s */
  result = g_malloc0 (total_length);

  /* start with 00 00 (just move starting offset up by 2) */
  pos = 2;

  /* Size Counter bytes */
  /* "easiest" way to handle 2-bytes size for counter is to hard-code logic for when we go to the 2nd byte */
  /* note this will not work in case any model ever supports more than 14 prints (assumed max is 10) */
  if (num_to_delete > 7)
    {
      memset (result + pos, 0x01, sizeof (guchar));
      pos += sizeof (guchar);
      memset (result + pos, ((num_to_delete - 8) * 0x20) + 0x07, sizeof (guchar));
      pos += sizeof (guchar);
    }
  else
    {
      /* first byte is 0x00, just skip it */
      pos += sizeof (guchar);
      memset (result + pos, (num_to_delete * 0x20) + 0x07, sizeof (guchar));
      pos += sizeof (guchar);
    }

  /* command prefix */
  memcpy (result + pos, cmd_delete_prefix, cmd_delete_prefix_len);
  pos += cmd_delete_prefix_len;

  /* 2-bytes size logic for counter again */
  if (num_to_delete > 7)
    {
      memset (result + pos, 0x01, sizeof (guchar));
      pos += sizeof (guchar);
      memset (result + pos, ((num_to_delete - 8) * 0x20), sizeof (guchar));
      pos += sizeof (guchar);
    }
  else
    {
      /* first byte is 0x00, just skip it */
      pos += sizeof (guchar);
      memset (result + pos, (num_to_delete * 0x20), sizeof (guchar));
      pos += sizeof (guchar);
    }

  /* append desired 32-byte fingerprint IDs */
  /* if passed a delete_print then fetch its data from the FpPrint */
  if (delete_print)
    {
      g_object_get (delete_print, "description", &print_description, NULL);
      g_object_get (delete_print, "fpi-data", &print_data, NULL);

      if (!g_variant_check_format_string (print_data, "(@ay)", FALSE))
        {
          /* if delete_print was passed then this was a "delete"; mark it failed */
          fpi_device_delete_complete (device,
                                      fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
          return NULL;
        }

      g_variant_get (print_data, "(@ay)", &print_data_id_var);
      print_data_id = g_variant_get_fixed_array (print_data_id_var, &print_data_id_len, sizeof (guchar));

      if (!g_str_has_prefix (print_description, "FP"))
        fp_dbg ("Fingerprint '%s' was not created by libfprint; deleting anyway.", print_description);

      fp_info ("Delete fingerprint %s (%s)", print_description, print_data_id);

      memcpy (result + pos, print_data_id, print_id_length);
    }
  /* Otherwise assume this is a "clear" - just loop through and append all enrolled IDs */
  else
    {
      for (int i=0; i < self->enrolled_num; i++)
        {
          enrolled_print_id = g_ptr_array_index (self->enrolled_ids, i);
          memcpy (result + pos + (print_id_length * i), enrolled_print_id, print_id_length);
        }
    }
  pos += body_length;

  result_cmd->cmd = result;
  result_cmd->cmd_length = total_length;
  return g_steal_pointer (&result_cmd);
}

static void
egismoc_clear_storage_cb (FpDevice *device,
                          guchar   *buffer_in,
                          gsize     length_in,
                          GError   *error)
{
  fp_dbg ("Clear storage callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  if (error)
    {
      fpi_device_clear_storage_complete (device, error);
      /* fpi_ssm_mark_failed (self->task_ssm, error); TODO trying to mark task as failed after completing with error throws exception? */
      return;
    }

  /* Check that the read payload indicates "success" with the delete */
  if (egismoc_validate_response_prefix (buffer_in,
                                        length_in,
                                        rsp_delete_success_prefix,
                                        rsp_delete_success_prefix_len))
    {
      fpi_ssm_next_state (self->task_ssm);
    }
  else
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Clear storage was not successfull");
      fpi_device_clear_storage_complete (device, error);
      /* fpi_ssm_mark_failed (self->task_ssm, error); TODO trying to mark task as failed after completing with error throws exception? */
    }
}

static void
egismoc_clear_storage_run_state (FpiSsm   *ssm,
                                 FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  EgisMocCommand *cmd = NULL;
  g_autoptr(GError) error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CLEAR_STORAGE_GET_ENROLLED_IDS_BEFORE:
      /* get enrolled_ids and enrolled_num from device for use building delete_cmd below */
      egismoc_fill_enrolled_ids (device);
      break;

    case CLEAR_STORAGE_CLEAR:
      cmd = egismoc_get_delete_cmd (device, NULL);
      cmd = egismoc_compose_cmd (cmd->cmd, cmd->cmd_length);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_clear_storage_cb);
      break;

    case CLEAR_STORAGE_GET_ENROLLED_IDS_AFTER:
      /* get enrolled_num from device again to check that device has actually been cleared */
      egismoc_fill_enrolled_ids (device);
      break;

    case CLEAR_STORAGE_COMPLETE:
      if (self->enrolled_num == 0)
        {
          fpi_device_clear_storage_complete (device, NULL);
          fpi_ssm_mark_completed (ssm);
        }
      else
        {
          error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                            "Clear storage submitted but storage on device is not empty.");
          fpi_device_clear_storage_complete (device, error);
          /* fpi_ssm_mark_failed (ssm, error); TODO trying to mark task as failed after completing with error throws exception? */
        }
      break;
    }
}

static void
egismoc_clear_storage (FpDevice *device)
{
  fp_dbg ("Clear storage");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  if (self->enrolled_num == 0)
    {
      fpi_device_clear_storage_complete (device,
                                         fpi_device_error_new (FP_DEVICE_ERROR_DATA_NOT_FOUND));
      return;
    }

  self->task_ssm = fpi_ssm_new (device,
                                egismoc_clear_storage_run_state,
                                CLEAR_STORAGE_STATES);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static void
egismoc_delete_cb (FpDevice *device,
                   guchar   *buffer_in,
                   gsize     length_in,
                   GError   *error)
{
  fp_dbg ("Delete callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  if (error)
    {
      fpi_device_delete_complete (device, error);
      /* fpi_ssm_mark_failed (self->task_ssm, error); TODO trying to mark task as failed after completing with error throws exception? */
      return;
    }

  /* Check that the read payload indicates "success" with the delete */
  if (egismoc_validate_response_prefix (buffer_in,
                                        length_in,
                                        rsp_delete_success_prefix,
                                        rsp_delete_success_prefix_len))
    {
      fpi_device_delete_complete (device, NULL);
      fpi_ssm_next_state (self->task_ssm);
    }
  else
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Delete print was not successfull");
      fpi_device_delete_complete (device, error);
      /* fpi_ssm_mark_failed (self->task_ssm, error); TODO trying to mark task as failed after completing with error throws exception? */
    }
}

static void
egismoc_delete_run_state (FpiSsm   *ssm,
                          FpDevice *device)
{
  EgisMocCommand *cmd = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DELETE_GET_ENROLLED_IDS:
      /* get enrolled_ids and enrolled_num from device for use building delete_cmd below */
      egismoc_fill_enrolled_ids (device);
      break;

    case DELETE_DELETE:
      cmd = egismoc_get_delete_cmd (device, fpi_ssm_get_data (ssm));
      cmd = egismoc_compose_cmd (cmd->cmd, cmd->cmd_length);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_delete_cb);
      break;
    }
}

static void
egismoc_delete (FpDevice *device)
{
  fp_dbg ("Delete");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  g_autoptr(FpPrint) delete_print = NULL;
  fpi_device_get_delete_data (device, &delete_print);

  self->task_ssm = fpi_ssm_new (device,
                                egismoc_delete_run_state,
                                DELETE_STATES);
  fpi_ssm_set_data (self->task_ssm, g_steal_pointer (&delete_print), NULL);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static void
egismoc_enroll_status_report (FpDevice     *device,
                              EnrollPrint  *enroll_print,
                              EnrollStatus  status,
                              GError       *error)
{
  switch (status)
    {
    case ENROLL_STATUS_DEVICE_FULL:
    case ENROLL_STATUS_DUPLICATE:
      fpi_device_enroll_complete (device, NULL, error);
      break;

    case ENROLL_STATUS_RETRY:
      fpi_device_enroll_progress (device, enroll_print->stage, NULL, error);
      break;

    case ENROLL_STATUS_PARTIAL_OK:
      enroll_print->stage++;
      fp_info ("Partial capture successful. Please touch the sensor again (%d/%d)",
               enroll_print->stage,
               EGISMOC_MAX_ENROLL_NUM);
      fpi_device_enroll_progress (device, enroll_print->stage, enroll_print->print, NULL);
      break;

    case ENROLL_STATUS_COMPLETE:
      fp_info ("Enrollment was successful!");
      fpi_device_enroll_complete (device, g_object_ref (enroll_print->print), NULL);
      break;

    default:
      if (error)
        fpi_device_enroll_complete (device, NULL, error);
      else
        fpi_device_enroll_complete (device, NULL,
                                    fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                              "Unknown error"));
    }
}

static void
egismoc_read_capture_cb (FpDevice *device,
                         guchar   *buffer_in,
                         gsize     length_in,
                         GError   *error)
{
  fp_dbg ("Read capture callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  EnrollPrint *enroll_print = fpi_ssm_get_data (self->task_ssm);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* Check that the read payload indicates "success" */
  if (egismoc_validate_response_prefix (buffer_in,
                                        length_in,
                                        rsp_read_success_prefix,
                                        rsp_read_success_prefix_len) &&
      egismoc_validate_response_suffix (buffer_in,
                                        length_in,
                                        rsp_read_success_suffix,
                                        rsp_read_success_suffix_len))
    {
      egismoc_enroll_status_report (device, enroll_print, ENROLL_STATUS_PARTIAL_OK, NULL);
    }
  else
    {
      /* If not success then the sensor can either report "off center" or "sensor is dirty" */

      /* "Off center" */
      if (egismoc_validate_response_prefix (buffer_in,
                                            length_in,
                                            rsp_read_offcenter_prefix,
                                            rsp_read_offcenter_prefix_len) &&
          egismoc_validate_response_suffix (buffer_in,
                                            length_in,
                                            rsp_read_offcenter_suffix,
                                            rsp_read_offcenter_suffix_len))
        {
          error = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);
        }

      /* "Sensor is dirty" */
      else if (egismoc_validate_response_prefix (buffer_in,
                                                 length_in,
                                                 rsp_read_dirty_prefix,
                                                 rsp_read_dirty_prefix_len))
        {
          error = fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                            "Your device is having trouble recognizing you. Make sure your sensor is clean.");
        }
      
      else
          error = fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                            "Unknown failure trying to read your finger. Please try again.");

      egismoc_enroll_status_report (device, enroll_print, ENROLL_STATUS_RETRY, error);
    }

  if (enroll_print->stage == EGISMOC_ENROLL_TIMES)
    fpi_ssm_next_state (self->task_ssm);
  else
    fpi_ssm_jump_to_state (self->task_ssm, ENROLL_CAPTURE_SENSOR_RESET);
}

static void
egismoc_enroll_check_cb (FpDevice *device,
                         guchar   *buffer_in,
                         gsize     length_in,
                         GError   *error)
{
  fp_dbg ("Enroll check callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* Check that the read payload reports "not yet enrolled" */
  if (egismoc_validate_response_prefix (buffer_in,
                                        length_in,
                                        rsp_check_not_yet_enrolled_prefix,
                                        rsp_check_not_yet_enrolled_prefix_len))
    {
      fpi_ssm_next_state (self->task_ssm);
    }
  else
    {
      error = fpi_device_error_new (FP_DEVICE_ERROR_DATA_DUPLICATE);
      egismoc_enroll_status_report (device, NULL, ENROLL_STATUS_DUPLICATE, error);
    }
}

/*
  Builds the full "check" payload which includes identifiers for all fingerprints which currently
  should exist on the storage. This payload is used during both enrollment and verify actions.
*/
static EgisMocCommand *
egismoc_get_check_cmd (FpDevice *device)
{
  fp_dbg ("Get check command");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  guchar *device_print_id = NULL;
  guchar *result = NULL;
  EgisMocCommand *result_cmd = g_new0 (EgisMocCommand, 1);
  size_t pos = 0;

  /*
    The final command body should contain:
    1) hard-coded 00 00
    2) 2-byte size indiciator, 20*Number enrolled identifiers plus 9 in form of: (enrolled_num + 1) * 0x20 + 0x09
       Since max prints can be higher than 7 then this goes up to 2 bytes (e9 + 9 = 109)
    3) Hard-coded prefix (cmd_check_prefix)
    4) 2-byte size indiciator, 20*Number of enrolled identifiers without plus 9 ((enrolled_num + 1) * 0x20)
    5) Hard-coded 32 * 0x00 bytes
    6) All of the currently registered prints in their 32-byte device identifiers (enrolled_list)
    7) Hard-coded suffix (cmd_check_suffix)
  */

  const size_t body_length = sizeof (guchar) * self->enrolled_num * EGISMOC_FINGERPRINT_DATA_SIZE;

  /* total_length is the 6 various bytes plus all other prefixes/suffixes and the body payload */
  const size_t total_length = (sizeof (guchar) * 6)
                              + cmd_check_prefix_len
                              + EGISMOC_CMD_CHECK_SEPARATOR_LENGTH
                              + body_length
                              + cmd_check_suffix_len;

  /* pre-fill entire payload with 00s */
  result = g_malloc0 (total_length);

  /* start with 00 00 (just move starting offset up by 2) */
  pos = 2;

  /* Size Counter bytes */
  /* "easiest" way to handle 2-bytes size for counter is to hard-code logic for when we go to the 2nd byte */
  /* note this will not work in case any model ever supports more than 14 prints (assumed max is 10) */
  if (self->enrolled_num > 6)
    {
      memset (result + pos, 0x01, sizeof (guchar));
      pos += sizeof (guchar);
      memset (result + pos, ((self->enrolled_num - 7) * 0x20) + 0x09, sizeof (guchar));
      pos += sizeof (guchar);
    }
  else
    {
      /* first byte is 0x00, just skip it */
      pos += sizeof (guchar);
      memset (result + pos, ((self->enrolled_num + 1) * 0x20) + 0x09, sizeof (guchar));
      pos += sizeof (guchar);
    }

  /* command prefix */
  memcpy (result + pos, cmd_check_prefix, cmd_check_prefix_len);
  pos += cmd_check_prefix_len;

  /* 2-bytes size logic for counter again */
  if (self->enrolled_num > 6)
    {
      memset (result + pos, 0x01, sizeof (guchar));
      pos += sizeof (guchar);
      memset (result + pos, (self->enrolled_num - 7) * 0x20, sizeof (guchar));
      pos += sizeof (guchar);
    }
  else
    {
      /* first byte is 0x00, just skip it */
      pos += sizeof (guchar);
      memset (result + pos, (self->enrolled_num + 1) * 0x20, sizeof (guchar));
      pos += sizeof (guchar);
    }

  /* add 00s "separator" to offset position */
  pos += EGISMOC_CMD_CHECK_SEPARATOR_LENGTH;

  /* append all currently registered 32-byte fingerprint IDs */
  const size_t print_id_length = sizeof (guchar) * EGISMOC_FINGERPRINT_DATA_SIZE;
  for (int i=0; i < self->enrolled_num; i++)
    {
      device_print_id = g_ptr_array_index (self->enrolled_ids, i);
      memcpy (result + pos + (print_id_length * i), device_print_id, print_id_length);
    }
  pos += body_length;

  /* command suffix */
  memcpy (result + pos, cmd_check_suffix, cmd_check_suffix_len);
  pos += cmd_check_suffix_len;

  result_cmd->cmd = result;
  result_cmd->cmd_length = total_length;
  return g_steal_pointer (&result_cmd);
}

static void
egismoc_enroll_run_state (FpiSsm   *ssm,
                          FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  EgisMocCommand *cmd = NULL;
  EnrollPrint *enroll_print = fpi_ssm_get_data (ssm);
  g_autofree guchar *device_print_id = NULL;
  g_autofree gchar *user_id = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENROLL_GET_ENROLLED_IDS:
      /* get enrolled_ids and enrolled_num from device for use in check stages below */
      egismoc_fill_enrolled_ids (device);
      break;

    case ENROLL_CHECK_ENROLLED_NUM:
      if (self->enrolled_num >= EGISMOC_MAX_ENROLL_NUM)
        {
          egismoc_enroll_status_report (device, enroll_print, ENROLL_STATUS_DEVICE_FULL,
                                        fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ENROLL_SENSOR_RESET:
      cmd = egismoc_compose_cmd (cmd_sensor_reset, cmd_sensor_reset_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_SENSOR_ENROLL:
      cmd = egismoc_compose_cmd (cmd_sensor_enroll, cmd_sensor_enroll_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_WAIT_FINGER:
      egismoc_wait_finger_on_sensor (ssm, device);
      break;

    case ENROLL_SENSOR_CHECK:
      cmd = egismoc_compose_cmd (cmd_sensor_check, cmd_sensor_check_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_CHECK:
      cmd = egismoc_get_check_cmd (device);
      cmd = egismoc_compose_cmd (cmd->cmd, cmd->cmd_length);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_enroll_check_cb);
      break;

    case ENROLL_START:
      cmd = egismoc_compose_cmd (cmd_enroll_starting, cmd_enroll_starting_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_CAPTURE_SENSOR_RESET:
      cmd = egismoc_compose_cmd (cmd_sensor_reset, cmd_sensor_reset_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_CAPTURE_SENSOR_START_CAPTURE:
      cmd = egismoc_compose_cmd (cmd_sensor_start_capture, cmd_sensor_start_capture_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_CAPTURE_WAIT_FINGER:
      egismoc_wait_finger_on_sensor (ssm, device);
      break;

    case ENROLL_CAPTURE_READ_RESPONSE:
      cmd = egismoc_compose_cmd (cmd_read_capture, cmd_read_capture_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_read_capture_cb);
      break;

    case ENROLL_COMMIT_START:
      cmd = egismoc_compose_cmd (cmd_commit_starting, cmd_commit_starting_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_COMMIT:
      user_id = fpi_print_generate_user_id (enroll_print->print);
      device_print_id = g_malloc0 (EGISMOC_FINGERPRINT_DATA_SIZE);
      memcpy (device_print_id, user_id, EGISMOC_FINGERPRINT_DATA_SIZE);

      fp_dbg ("New fingerprint ID: %s", device_print_id);

      egismoc_set_print_data (enroll_print->print, device_print_id);

      /* create new cmd with a dynamic payload of cmd_new_print_prefix + device_print_id */
      cmd = g_new0 (EgisMocCommand, 1);
      cmd->cmd_length = cmd_new_print_prefix_len + EGISMOC_FINGERPRINT_DATA_SIZE;
      cmd->cmd = g_malloc0 (cmd->cmd_length);
      memcpy (cmd->cmd, cmd_new_print_prefix, cmd_new_print_prefix_len);
      memcpy (cmd->cmd + cmd_new_print_prefix_len, device_print_id, EGISMOC_FINGERPRINT_DATA_SIZE);

      /* compose the final command with the correct prefix and check bytes */
      cmd = egismoc_compose_cmd (cmd->cmd, cmd->cmd_length);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_COMMIT_SENSOR_RESET:
      cmd = egismoc_compose_cmd (cmd_sensor_reset, cmd_sensor_reset_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case ENROLL_COMPLETE:
      egismoc_enroll_status_report (device, enroll_print, ENROLL_STATUS_COMPLETE, NULL);
      fpi_ssm_next_state (ssm);
      break;
    }
}

static void
egismoc_enroll (FpDevice *device)
{
  fp_dbg ("Enroll");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  EnrollPrint *enroll_print = g_new0 (EnrollPrint, 1);

  fpi_device_get_enroll_data (device, &enroll_print->print);
  enroll_print->stage = 0;

  self->task_ssm = fpi_ssm_new (device, egismoc_enroll_run_state, ENROLL_STATES);
  fpi_ssm_set_data (self->task_ssm, g_steal_pointer (&enroll_print), g_free);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static void
egismoc_identify_check_cb (FpDevice *device,
                           guchar   *buffer_in,
                           gsize     length_in,
                           GError   *error)
{
  fp_dbg ("Identify check callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  guchar device_print_id[EGISMOC_FINGERPRINT_DATA_SIZE];
  FpPrint *print = NULL;
  FpPrint *verify_print = NULL;
  GPtrArray *prints;
  gboolean found = FALSE;
  guint index;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* Check that the read payload indicates "match" */
  if (egismoc_validate_response_prefix (buffer_in,
                                        length_in,
                                        rsp_identify_match_prefix,
                                        rsp_identify_match_prefix_len) &&
      egismoc_validate_response_suffix (buffer_in,
                                        length_in,
                                        rsp_identify_match_suffix,
                                        rsp_identify_match_suffix_len))
    {
      /*
        On success, there is a 32 byte array of "something"(?) in chars 14-45
        and then the 32 byte array ID of the matched print comes as chars 46-77
      */
      memcpy (device_print_id,
              buffer_in + EGISMOC_IDENTIFY_RESPONSE_PRINT_ID_OFFSET,
              EGISMOC_FINGERPRINT_DATA_SIZE);

      /* Create a new print from this ID and then see if it matches the one indicated */
      print = fp_print_new (device);
      egismoc_set_print_data (print, device_print_id);

      if (!print)
        {
          fpi_ssm_mark_failed (self->task_ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                         "Failed to build a print from device response."));
          return;
        }

      fp_info ("Identify successful for: %s", fp_print_get_description (print));

      if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_IDENTIFY)
        {
          fpi_device_get_identify_data (device, &prints);
          found = g_ptr_array_find_with_equal_func (prints,
                                                    print,
                                                    (GEqualFunc) fp_print_equal,
                                                    &index);

          if (found)
            fpi_device_identify_report (device, g_ptr_array_index (prints, index), print, NULL);
          else
            fpi_device_identify_report (device, NULL, print, NULL);

          fpi_ssm_next_state (self->task_ssm);
        }
      else
        {
          fpi_device_get_verify_data (device, &verify_print);
          fp_info ("Verifying against: %s", fp_print_get_description (verify_print));

          if (fp_print_equal (verify_print, print))
            fpi_device_verify_report (device, FPI_MATCH_SUCCESS, print, NULL);
          else
            fpi_device_verify_report (device, FPI_MATCH_FAIL, print, NULL);

          fpi_ssm_next_state (self->task_ssm);
        }
    }
  /* If device was successfully read but it was a "not matched" */
  else if (egismoc_validate_response_prefix (buffer_in,
                                             length_in,
                                             rsp_identify_notmatch_prefix,
                                             rsp_identify_notmatch_prefix_len))
    {
      fp_info ("Print was not identified by the device");

      if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY)
        {
          fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
          fpi_ssm_next_state (self->task_ssm);
        }
      else
        {
          fpi_device_identify_report (device, NULL, NULL, NULL);
          fpi_ssm_next_state (self->task_ssm);
        }
    }
  else
    {
      fpi_ssm_mark_failed (self->task_ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                    "Unrecognized response from device."));
    }
}

static void
egismoc_identify_run_state (FpiSsm   *ssm,
                            FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  EgisMocCommand *cmd = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case IDENTIFY_GET_ENROLLED_IDS:
      /* get enrolled_ids and enrolled_num from device for use in check stages below */
      egismoc_fill_enrolled_ids (device);
      break;

    case IDENTIFY_CHECK_ENROLLED_NUM:
      if (self->enrolled_num == 0)
        {
          fpi_ssm_mark_failed (g_steal_pointer (&self->task_ssm),
                               fpi_device_error_new (FP_DEVICE_ERROR_DATA_NOT_FOUND));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case IDENTIFY_SENSOR_RESET:
      cmd = egismoc_compose_cmd (cmd_sensor_reset, cmd_sensor_reset_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case IDENTIFY_SENSOR_IDENTIFY:
      cmd = egismoc_compose_cmd (cmd_sensor_identify, cmd_sensor_identify_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case IDENTIFY_WAIT_FINGER:
      egismoc_wait_finger_on_sensor (ssm, device);
      break;

    case IDENTIFY_SENSOR_CHECK:
      cmd = egismoc_compose_cmd (cmd_sensor_check, cmd_sensor_check_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    case IDENTIFY_CHECK:
      cmd = egismoc_get_check_cmd (device);
      cmd = egismoc_compose_cmd (cmd->cmd, cmd->cmd_length);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_identify_check_cb);
      break;

    case IDENTIFY_COMPLETE_SENSOR_RESET:
      cmd = egismoc_compose_cmd (cmd_sensor_reset, cmd_sensor_reset_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_task_ssm_next_state_cb);
      break;

    /*
      In Windows, the driver seems at this point to then immediately take another read from the sensor;
      this is suspected to be an on-chip "verify". However, because the user's finger is still on the
      sensor from the identify, then it seems to always return positive. We will consider this extra
      step unnecessary and just skip it in this driver. This driver will instead handle matching of the
      FpPrint from the gallery in the "verify" case of the callback egismoc_identify_check_cb.
    */

    case IDENTIFY_COMPLETE:
      if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_IDENTIFY)
        fpi_device_identify_complete (device, NULL);
      else
        fpi_device_verify_complete(device, NULL);

      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
egismoc_identify_verify (FpDevice *device)
{
  fp_dbg ("Identify or Verify");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  self->task_ssm = fpi_ssm_new (device, egismoc_identify_run_state, IDENTIFY_STATES);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static void
egismoc_fw_version_cb (FpDevice *device,
                       guchar   *buffer_in,
                       gsize     length_in,
                       GError   *error)
{
  fp_dbg ("Firmware version callback");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autofree guchar *fw_version = NULL;
  size_t prefix_length;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* Check that the read payload indicates "success" */
  if (!egismoc_validate_response_suffix (buffer_in,
                                         length_in,
                                         rsp_fw_version_suffix,
                                         rsp_fw_version_suffix_len))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Device firmware response was not valid."));
      return;
    }

  /*
    FW Version is 12 bytes: a carriage return (0x0d) plus the version string itself.
    Always skip [the read prefix] + [2 * check bytes] + [3 * 0x00] that come with every payload
    Then we will also skip the carriage return and take all but the last 2 bytes as the FW Version
  */
  prefix_length = egismoc_read_prefix_len + 2 + 3 + 1;
  fw_version = g_malloc0 (length_in - prefix_length - rsp_fw_version_suffix_len);
  memcpy (fw_version,
          buffer_in + prefix_length,
          length_in - prefix_length - rsp_fw_version_suffix_len);

  fp_info ("Device firmware version is %s", fw_version);

  fpi_ssm_next_state (self->task_ssm);
}

static void
egismoc_dev_init_done (FpiSsm   *ssm,
                            FpDevice *device,
                            GError   *error)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  if (error)
    g_usb_device_release_interface (fpi_device_get_usb_device (device), 0, 0, NULL);

  fpi_device_open_complete (FP_DEVICE (self), error);
}

static void
egismoc_dev_init_handler (FpiSsm   *ssm,
                          FpDevice *device)
{
  g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (device);

  EgisMocCommand *cmd = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DEV_INIT_CONTROL1:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     32, 0x0000, 4, 16);
      goto send_control;
      break;

    case DEV_INIT_CONTROL2:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     32, 0x0000, 4, 40);
      goto send_control;
      break;

    case DEV_INIT_CONTROL3:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_STANDARD,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     0, 0x0000, 0, 2);
      goto send_control;
      break;

    case DEV_INIT_CONTROL4:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_STANDARD,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     0, 0x0000, 0, 2);
      goto send_control;
      break;

    case DEV_INIT_CONTROL5:
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     82, 0x0000, 0, 8);
      goto send_control;
      break;

    case DEV_GET_FW_VERSION:
      cmd = egismoc_compose_cmd (cmd_fw_version, cmd_fw_version_len);
      egismoc_get_cmd (device, g_steal_pointer (&cmd), egismoc_fw_version_cb);
      break;
    }

  return;

send_control:
  transfer->ssm = ssm;
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit (g_steal_pointer (&transfer),
                          EGISMOC_USB_CONTROL_TIMEOUT,
                          NULL,
                          fpi_ssm_usb_transfer_cb,
                          NULL);
}

static void
egismoc_open (FpDevice *device)
{
  fp_dbg ("Opening device");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  GError *error = NULL;

  self->interrupt_cancellable = g_cancellable_new ();

  if (!g_usb_device_reset (fpi_device_get_usb_device (device), &error))
    goto error;

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device), 0, 0, &error))
    goto error;

  self->task_ssm = fpi_ssm_new (FP_DEVICE (self), egismoc_dev_init_handler, DEV_INIT_STATES);
  fpi_ssm_start (self->task_ssm, egismoc_dev_init_done);
  return;

error:
  return fpi_device_open_complete (FP_DEVICE (self), error);
}

static void
egismoc_cancel (FpDevice *device)
{
  fp_dbg ("Cancel");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  g_cancellable_cancel (self->interrupt_cancellable);
  g_clear_object (&self->interrupt_cancellable);
  self->interrupt_cancellable = g_cancellable_new ();
}

static void
egismoc_close (FpDevice *device)
{
  fp_dbg ("Closing device");
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  GError *error = NULL;

  egismoc_cancel (device);

  self->task_ssm = NULL;
  self->cmd_ssm = NULL;
  self->cmd_transfer = NULL;
  g_clear_object (&self->interrupt_cancellable);
  self->enrolled_ids = NULL;

  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)), 0, 0, &error);
  fpi_device_close_complete (FP_DEVICE (self), error);
}

static void
fpi_device_egismoc_init (FpiDeviceEgisMoc *self)
{
  G_DEBUG_HERE ();
}

static void
fpi_device_egismoc_class_init (FpiDeviceEgisMocClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = EGISMOC_DRIVER_FULLNAME;

  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = egismoc_id_table;
  dev_class->nr_enroll_stages = EGISMOC_ENROLL_TIMES;
  dev_class->temp_hot_seconds = 0; /* device should be "always off" unless being used */

  dev_class->open = egismoc_open;
  dev_class->cancel = egismoc_cancel;
  dev_class->suspend = egismoc_cancel;
  dev_class->close = egismoc_close;
  dev_class->identify = egismoc_identify_verify;
  dev_class->verify = egismoc_identify_verify;
  dev_class->enroll = egismoc_enroll;
  dev_class->delete = egismoc_delete;
  dev_class->clear_storage = egismoc_clear_storage;
  dev_class->list = egismoc_list;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;
  /*
    TODO: in gnome-control-center ("Settings") it seems to do an "Identify" before enrollment, and then blocks on the
    software side if the finger is already enrolled. Is FP_DEVICE_FEATURE_DUPLICATES_CHECK controlling that or is that
    a gnome-control-center thing?
    In any case, the aim of the code of this driver during enrollment is to fail duplicates based on response from the
    device (see egismoc_enroll_check_cb).
  */
}
