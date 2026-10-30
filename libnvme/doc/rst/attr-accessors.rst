.. c:function:: int libnvme_ctrl_get_numa_node (const struct libnvme_ctrl *p, const char **numa_node, const char *dflt)

   Get numa_node.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **numa_node``
  Where to store the value on success.

``const char *dflt``
  Value to store in **numa_node** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ctrl_get_queue_count (const struct libnvme_ctrl *p, const char **queue_count, const char *dflt)

   Get queue_count.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **queue_count``
  Where to store the value on success.

``const char *dflt``
  Value to store in **queue_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ctrl_get_sqsize (const struct libnvme_ctrl *p, const char **sqsize, const char *dflt)

   Get sqsize.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **sqsize``
  Where to store the value on success.

``const char *dflt``
  Value to store in **sqsize** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ctrl_get_command_error_count (const struct libnvme_ctrl *p, long *command_error_count, long dflt)

   Get command_error_count.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``long *command_error_count``
  Where to store the value on success.

``long dflt``
  Value to store in **command_error_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ctrl_get_reset_count (const struct libnvme_ctrl *p, long *reset_count, long dflt)

   Get reset_count.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``long *reset_count``
  Where to store the value on success.

``long dflt``
  Value to store in **reset_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ctrl_get_reconnect_count (const struct libnvme_ctrl *p, long *reconnect_count, long dflt)

   Get reconnect_count.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``long *reconnect_count``
  Where to store the value on success.

``long dflt``
  Value to store in **reconnect_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_ctrl_set_firmware (struct libnvme_ctrl *p, const char *firmware)

   Set firmware.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *firmware``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_ctrl_get_firmware (const struct libnvme_ctrl *p, const char **firmware, const char *dflt)

   Get firmware.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **firmware``
  Where to store the value on success.

``const char *dflt``
  Value to store in **firmware** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_ctrl_set_model (struct libnvme_ctrl *p, const char *model)

   Set model.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *model``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_ctrl_get_model (const struct libnvme_ctrl *p, const char **model, const char *dflt)

   Get model.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **model``
  Where to store the value on success.

``const char *dflt``
  Value to store in **model** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_ctrl_set_serial (struct libnvme_ctrl *p, const char *serial)

   Set serial.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *serial``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_ctrl_get_serial (const struct libnvme_ctrl *p, const char **serial, const char *dflt)

   Get serial.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **serial``
  Where to store the value on success.

``const char *dflt``
  Value to store in **serial** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_ctrl_set_cntrltype (struct libnvme_ctrl *p, const char *cntrltype)

   Set cntrltype.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *cntrltype``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_ctrl_get_cntrltype (const struct libnvme_ctrl *p, const char **cntrltype, const char *dflt)

   Get cntrltype.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **cntrltype``
  Where to store the value on success.

``const char *dflt``
  Value to store in **cntrltype** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_ctrl_set_cntlid (struct libnvme_ctrl *p, const char *cntlid)

   Set cntlid.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *cntlid``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_ctrl_get_cntlid (const struct libnvme_ctrl *p, const char **cntlid, const char *dflt)

   Get cntlid.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **cntlid``
  Where to store the value on success.

``const char *dflt``
  Value to store in **cntlid** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_ctrl_set_dctype (struct libnvme_ctrl *p, const char *dctype)

   Set dctype.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *dctype``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_ctrl_get_dctype (const struct libnvme_ctrl *p, const char **dctype, const char *dflt)

   Get dctype.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **dctype``
  Where to store the value on success.

``const char *dflt``
  Value to store in **dctype** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ctrl_get_phy_slot (const struct libnvme_ctrl *p, const char **phy_slot, const char *dflt)

   Get phy_slot.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **phy_slot``
  Where to store the value on success.

``const char *dflt``
  Value to store in **phy_slot** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_ctrl_set_kxchap_host_key (struct libnvme_ctrl *p, const char *kxchap_host_key)

   Set kxchap_host_key.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *kxchap_host_key``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_ctrl_get_kxchap_host_key (const struct libnvme_ctrl *p, const char **kxchap_host_key, const char *dflt)

   Get kxchap_host_key.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **kxchap_host_key``
  Where to store the value on success.

``const char *dflt``
  Value to store in **kxchap_host_key** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_ctrl_set_kxchap_ctrl_key (struct libnvme_ctrl *p, const char *kxchap_ctrl_key)

   Set kxchap_ctrl_key.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *kxchap_ctrl_key``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_ctrl_get_kxchap_ctrl_key (const struct libnvme_ctrl *p, const char **kxchap_ctrl_key, const char *dflt)

   Get kxchap_ctrl_key.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **kxchap_ctrl_key``
  Where to store the value on success.

``const char *dflt``
  Value to store in **kxchap_ctrl_key** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_ctrl_set_keyring (struct libnvme_ctrl *p, const char *keyring)

   Set keyring.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *keyring``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_ctrl_get_keyring (const struct libnvme_ctrl *p, const char **keyring, const char *dflt)

   Get keyring.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

``const char **keyring``
  Where to store the value on success.

``const char *dflt``
  Value to store in **keyring** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_path_get_ana_state (const struct libnvme_path *p, const char **ana_state, const char *dflt)

   Get ana_state.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

``const char **ana_state``
  Where to store the value on success.

``const char *dflt``
  Value to store in **ana_state** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_path_get_numa_nodes (const struct libnvme_path *p, const char **numa_nodes, const char *dflt)

   Get numa_nodes.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

``const char **numa_nodes``
  Where to store the value on success.

``const char *dflt``
  Value to store in **numa_nodes** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_path_get_grpid (const struct libnvme_path *p, int *grpid, int dflt)

   Get grpid.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

``int *grpid``
  Where to store the value on success.

``int dflt``
  Value to store in **grpid** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_path_get_queue_depth (const struct libnvme_path *p, int *queue_depth, int dflt)

   Get queue_depth.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

``int *queue_depth``
  Where to store the value on success.

``int dflt``
  Value to store in **queue_depth** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_path_get_multipath_failover_count (const struct libnvme_path *p, long *multipath_failover_count, long dflt)

   Get multipath_failover_count.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

``long *multipath_failover_count``
  Where to store the value on success.

``long dflt``
  Value to store in **multipath_failover_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_path_get_command_retry_count (const struct libnvme_path *p, long *command_retry_count, long dflt)

   Get command_retry_count.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

``long *command_retry_count``
  Where to store the value on success.

``long dflt``
  Value to store in **command_retry_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_path_get_command_error_count (const struct libnvme_path *p, long *command_error_count, long dflt)

   Get command_error_count.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

``long *command_error_count``
  Where to store the value on success.

``long dflt``
  Value to store in **command_error_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_lba_size (const struct libnvme_ns *p, int *lba_size, int dflt)

   Get lba_size.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``int *lba_size``
  Where to store the value on success.

``int dflt``
  Value to store in **lba_size** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_lba_shift (const struct libnvme_ns *p, int *lba_shift, int dflt)

   Get lba_shift.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``int *lba_shift``
  Where to store the value on success.

``int dflt``
  Value to store in **lba_shift** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_lba_count (const struct libnvme_ns *p, uint64_t *lba_count, uint64_t dflt)

   Get lba_count.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``uint64_t *lba_count``
  Where to store the value on success.

``uint64_t dflt``
  Value to store in **lba_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_lba_util (const struct libnvme_ns *p, uint64_t *lba_util, uint64_t dflt)

   Get lba_util.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``uint64_t *lba_util``
  Where to store the value on success.

``uint64_t dflt``
  Value to store in **lba_util** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_meta_size (const struct libnvme_ns *p, int *meta_size, int dflt)

   Get meta_size.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``int *meta_size``
  Where to store the value on success.

``int dflt``
  Value to store in **meta_size** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_csi (const struct libnvme_ns *p, enum nvme_csi *csi, enum nvme_csi dflt)

   Get csi.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``enum nvme_csi *csi``
  Where to store the value on success.

``enum nvme_csi dflt``
  Value to store in **csi** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_eui64 (const struct libnvme_ns *p, const uint8_t **eui64, const uint8_t *dflt)

   Get eui64.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``const uint8_t **eui64``
  Where to store the value on success.

``const uint8_t *dflt``
  Value to store in **eui64** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_nguid (const struct libnvme_ns *p, const uint8_t **nguid, const uint8_t *dflt)

   Get nguid.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``const uint8_t **nguid``
  Where to store the value on success.

``const uint8_t *dflt``
  Value to store in **nguid** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_uuid (const struct libnvme_ns *p, const unsigned char **uuid, const unsigned char *dflt)

   Get uuid.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``const unsigned char **uuid``
  Where to store the value on success.

``const unsigned char *dflt``
  Value to store in **uuid** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_wwid (const struct libnvme_ns *p, const char **wwid, const char *dflt)

   Get wwid.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``const char **wwid``
  Where to store the value on success.

``const char *dflt``
  Value to store in **wwid** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_command_retry_count (const struct libnvme_ns *p, long *command_retry_count, long dflt)

   Get command_retry_count.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``long *command_retry_count``
  Where to store the value on success.

``long dflt``
  Value to store in **command_retry_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_command_error_count (const struct libnvme_ns *p, long *command_error_count, long dflt)

   Get command_error_count.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``long *command_error_count``
  Where to store the value on success.

``long dflt``
  Value to store in **command_error_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_io_requeue_no_usable_path_count (const struct libnvme_ns *p, long *io_requeue_no_usable_path_count, long dflt)

   Getter.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``long *io_requeue_no_usable_path_count``
  Where to store the value on success.

``long dflt``
  Value to store in **io_requeue_no_usable_path_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_ns_get_io_fail_no_available_path_count (const struct libnvme_ns *p, long *io_fail_no_available_path_count, long dflt)

   Getter.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

``long *io_fail_no_available_path_count``
  Where to store the value on success.

``long dflt``
  Value to store in **io_fail_no_available_path_count** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_subsystem_set_model (struct libnvme_subsystem *p, const char *model)

   Set model.

**Parameters**

``struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to update.

``const char *model``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_subsystem_get_model (const struct libnvme_subsystem *p, const char **model, const char *dflt)

   Get model.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

``const char **model``
  Where to store the value on success.

``const char *dflt``
  Value to store in **model** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_subsystem_set_serial (struct libnvme_subsystem *p, const char *serial)

   Set serial.

**Parameters**

``struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to update.

``const char *serial``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_subsystem_get_serial (const struct libnvme_subsystem *p, const char **serial, const char *dflt)

   Get serial.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

``const char **serial``
  Where to store the value on success.

``const char *dflt``
  Value to store in **serial** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: void libnvme_subsystem_set_firmware (struct libnvme_subsystem *p, const char *firmware)

   Set firmware.

**Parameters**

``struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to update.

``const char *firmware``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: int libnvme_subsystem_get_firmware (const struct libnvme_subsystem *p, const char **firmware, const char *dflt)

   Get firmware.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

``const char **firmware``
  Where to store the value on success.

``const char *dflt``
  Value to store in **firmware** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


.. c:function:: int libnvme_subsystem_get_iopolicy (const struct libnvme_subsystem *p, const char **iopolicy, const char *dflt)

   Get iopolicy.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

``const char **iopolicy``
  Where to store the value on success.

``const char *dflt``
  Value to store in **iopolicy** on failure.

**Return**

0 on success, -ENOENT if the attribute does not
        exist, or a negative errno on failure.


