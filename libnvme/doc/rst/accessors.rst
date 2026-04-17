.. c:function:: void libnvme_fabrics_config_set_queue_size (struct libnvme_fabrics_config *p, int queue_size)

   Set queue_size.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``int queue_size``
  Value to assign to the queue_size field.


.. c:function:: int libnvme_fabrics_config_get_queue_size (const struct libnvme_fabrics_config *p)

   Get queue_size.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the queue_size field.


.. c:function:: void libnvme_fabrics_config_set_nr_io_queues (struct libnvme_fabrics_config *p, int nr_io_queues)

   Set nr_io_queues.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``int nr_io_queues``
  Value to assign to the nr_io_queues field.


.. c:function:: int libnvme_fabrics_config_get_nr_io_queues (const struct libnvme_fabrics_config *p)

   Get nr_io_queues.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the nr_io_queues field.


.. c:function:: void libnvme_fabrics_config_set_reconnect_delay (struct libnvme_fabrics_config *p, int reconnect_delay)

   Set reconnect_delay.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``int reconnect_delay``
  Value to assign to the reconnect_delay field.


.. c:function:: int libnvme_fabrics_config_get_reconnect_delay (const struct libnvme_fabrics_config *p)

   Get reconnect_delay.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the reconnect_delay field.


.. c:function:: void libnvme_fabrics_config_set_ctrl_loss_tmo (struct libnvme_fabrics_config *p, int ctrl_loss_tmo)

   Set ctrl_loss_tmo.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``int ctrl_loss_tmo``
  Value to assign to the ctrl_loss_tmo field.


.. c:function:: int libnvme_fabrics_config_get_ctrl_loss_tmo (const struct libnvme_fabrics_config *p)

   Get ctrl_loss_tmo.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the ctrl_loss_tmo field.


.. c:function:: void libnvme_fabrics_config_set_fast_io_fail_tmo (struct libnvme_fabrics_config *p, int fast_io_fail_tmo)

   Set fast_io_fail_tmo.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``int fast_io_fail_tmo``
  Value to assign to the fast_io_fail_tmo field.


.. c:function:: int libnvme_fabrics_config_get_fast_io_fail_tmo (const struct libnvme_fabrics_config *p)

   Get fast_io_fail_tmo.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the fast_io_fail_tmo field.


.. c:function:: void libnvme_fabrics_config_set_keep_alive_tmo (struct libnvme_fabrics_config *p, int keep_alive_tmo)

   Set keep_alive_tmo.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``int keep_alive_tmo``
  Value to assign to the keep_alive_tmo field.


.. c:function:: int libnvme_fabrics_config_get_keep_alive_tmo (const struct libnvme_fabrics_config *p)

   Get keep_alive_tmo.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the keep_alive_tmo field.


.. c:function:: void libnvme_fabrics_config_set_nr_write_queues (struct libnvme_fabrics_config *p, int nr_write_queues)

   Set nr_write_queues.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``int nr_write_queues``
  Value to assign to the nr_write_queues field.


.. c:function:: int libnvme_fabrics_config_get_nr_write_queues (const struct libnvme_fabrics_config *p)

   Get nr_write_queues.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the nr_write_queues field.


.. c:function:: void libnvme_fabrics_config_set_nr_poll_queues (struct libnvme_fabrics_config *p, int nr_poll_queues)

   Set nr_poll_queues.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``int nr_poll_queues``
  Value to assign to the nr_poll_queues field.


.. c:function:: int libnvme_fabrics_config_get_nr_poll_queues (const struct libnvme_fabrics_config *p)

   Get nr_poll_queues.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the nr_poll_queues field.


.. c:function:: void libnvme_fabrics_config_set_tos (struct libnvme_fabrics_config *p, int tos)

   Set tos.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``int tos``
  Value to assign to the tos field.


.. c:function:: int libnvme_fabrics_config_get_tos (const struct libnvme_fabrics_config *p)

   Get tos.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the tos field.


.. c:function:: void libnvme_fabrics_config_set_keyring_id (struct libnvme_fabrics_config *p, long keyring_id)

   Set keyring_id.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``long keyring_id``
  Value to assign to the keyring_id field.


.. c:function:: long libnvme_fabrics_config_get_keyring_id (const struct libnvme_fabrics_config *p)

   Get keyring_id.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the keyring_id field.


.. c:function:: void libnvme_fabrics_config_set_tls_key_id (struct libnvme_fabrics_config *p, long tls_key_id)

   Set tls_key_id.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``long tls_key_id``
  Value to assign to the tls_key_id field.


.. c:function:: long libnvme_fabrics_config_get_tls_key_id (const struct libnvme_fabrics_config *p)

   Get tls_key_id.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the tls_key_id field.


.. c:function:: void libnvme_fabrics_config_set_tls_configured_key_id (struct libnvme_fabrics_config *p, long tls_configured_key_id)

   Set tls_configured_key_id.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``long tls_configured_key_id``
  Value to assign to the tls_configured_key_id field.


.. c:function:: long libnvme_fabrics_config_get_tls_configured_key_id (const struct libnvme_fabrics_config *p)

   Get tls_configured_key_id.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the tls_configured_key_id field.


.. c:function:: void libnvme_fabrics_config_set_duplicate_connect (struct libnvme_fabrics_config *p, bool duplicate_connect)

   Set duplicate_connect.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``bool duplicate_connect``
  Value to assign to the duplicate_connect field.


.. c:function:: bool libnvme_fabrics_config_get_duplicate_connect (const struct libnvme_fabrics_config *p)

   Get duplicate_connect.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the duplicate_connect field.


.. c:function:: void libnvme_fabrics_config_set_disable_sqflow (struct libnvme_fabrics_config *p, bool disable_sqflow)

   Set disable_sqflow.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``bool disable_sqflow``
  Value to assign to the disable_sqflow field.


.. c:function:: bool libnvme_fabrics_config_get_disable_sqflow (const struct libnvme_fabrics_config *p)

   Get disable_sqflow.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the disable_sqflow field.


.. c:function:: void libnvme_fabrics_config_set_hdr_digest (struct libnvme_fabrics_config *p, bool hdr_digest)

   Set hdr_digest.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``bool hdr_digest``
  Value to assign to the hdr_digest field.


.. c:function:: bool libnvme_fabrics_config_get_hdr_digest (const struct libnvme_fabrics_config *p)

   Get hdr_digest.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the hdr_digest field.


.. c:function:: void libnvme_fabrics_config_set_data_digest (struct libnvme_fabrics_config *p, bool data_digest)

   Set data_digest.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``bool data_digest``
  Value to assign to the data_digest field.


.. c:function:: bool libnvme_fabrics_config_get_data_digest (const struct libnvme_fabrics_config *p)

   Get data_digest.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the data_digest field.


.. c:function:: void libnvme_fabrics_config_set_tls (struct libnvme_fabrics_config *p, bool tls)

   Set tls.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``bool tls``
  Value to assign to the tls field.


.. c:function:: bool libnvme_fabrics_config_get_tls (const struct libnvme_fabrics_config *p)

   Get tls.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the tls field.


.. c:function:: void libnvme_fabrics_config_set_concat (struct libnvme_fabrics_config *p, bool concat)

   Set concat.

**Parameters**

``struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to update.

``bool concat``
  Value to assign to the concat field.


.. c:function:: bool libnvme_fabrics_config_get_concat (const struct libnvme_fabrics_config *p)

   Get concat.

**Parameters**

``const struct libnvme_fabrics_config *p``
  The :c:type:`struct libnvme_fabrics_config <libnvme_fabrics_config>` instance to query.

**Return**

The value of the concat field.


.. c:function:: void libnvme_path_set_name (struct libnvme_path *p, const char *name)

   Set name.

**Parameters**

``struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to update.

``const char *name``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_path_get_name (const struct libnvme_path *p)

   Get name.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

**Return**

The value of the name field, or NULL if not set.


.. c:function:: void libnvme_path_set_sysfs_dir (struct libnvme_path *p, const char *sysfs_dir)

   Set sysfs_dir.

**Parameters**

``struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to update.

``const char *sysfs_dir``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_path_get_sysfs_dir (const struct libnvme_path *p)

   Get sysfs_dir.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

**Return**

The value of the sysfs_dir field, or NULL if not set.


.. c:function:: void libnvme_path_set_ana_state (struct libnvme_path *p, const char *ana_state)

   Set ana_state.

**Parameters**

``struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to update.

``const char *ana_state``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_path_get_ana_state (const struct libnvme_path *p)

   Get ana_state.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

**Return**

The value of the ana_state field, or NULL if not set.


.. c:function:: void libnvme_path_set_numa_nodes (struct libnvme_path *p, const char *numa_nodes)

   Set numa_nodes.

**Parameters**

``struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to update.

``const char *numa_nodes``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_path_get_numa_nodes (const struct libnvme_path *p)

   Get numa_nodes.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

**Return**

The value of the numa_nodes field, or NULL if not set.


.. c:function:: void libnvme_path_set_grpid (struct libnvme_path *p, int grpid)

   Set grpid.

**Parameters**

``struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to update.

``int grpid``
  Value to assign to the grpid field.


.. c:function:: int libnvme_path_get_grpid (const struct libnvme_path *p)

   Get grpid.

**Parameters**

``const struct libnvme_path *p``
  The :c:type:`struct libnvme_path <libnvme_path>` instance to query.

**Return**

The value of the grpid field.


.. c:function:: void libnvme_ns_set_nsid (struct libnvme_ns *p, __u32 nsid)

   Set nsid.

**Parameters**

``struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to update.

``__u32 nsid``
  Value to assign to the nsid field.


.. c:function:: __u32 libnvme_ns_get_nsid (const struct libnvme_ns *p)

   Get nsid.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

**Return**

The value of the nsid field.


.. c:function:: void libnvme_ns_set_name (struct libnvme_ns *p, const char *name)

   Set name.

**Parameters**

``struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to update.

``const char *name``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_ns_get_name (const struct libnvme_ns *p)

   Get name.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

**Return**

The value of the name field, or NULL if not set.


.. c:function:: void libnvme_ns_set_sysfs_dir (struct libnvme_ns *p, const char *sysfs_dir)

   Set sysfs_dir.

**Parameters**

``struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to update.

``const char *sysfs_dir``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_ns_get_sysfs_dir (const struct libnvme_ns *p)

   Get sysfs_dir.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

**Return**

The value of the sysfs_dir field, or NULL if not set.


.. c:function:: void libnvme_ns_set_lba_shift (struct libnvme_ns *p, int lba_shift)

   Set lba_shift.

**Parameters**

``struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to update.

``int lba_shift``
  Value to assign to the lba_shift field.


.. c:function:: int libnvme_ns_get_lba_shift (const struct libnvme_ns *p)

   Get lba_shift.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

**Return**

The value of the lba_shift field.


.. c:function:: void libnvme_ns_set_lba_size (struct libnvme_ns *p, int lba_size)

   Set lba_size.

**Parameters**

``struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to update.

``int lba_size``
  Value to assign to the lba_size field.


.. c:function:: int libnvme_ns_get_lba_size (const struct libnvme_ns *p)

   Get lba_size.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

**Return**

The value of the lba_size field.


.. c:function:: void libnvme_ns_set_meta_size (struct libnvme_ns *p, int meta_size)

   Set meta_size.

**Parameters**

``struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to update.

``int meta_size``
  Value to assign to the meta_size field.


.. c:function:: int libnvme_ns_get_meta_size (const struct libnvme_ns *p)

   Get meta_size.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

**Return**

The value of the meta_size field.


.. c:function:: void libnvme_ns_set_lba_count (struct libnvme_ns *p, uint64_t lba_count)

   Set lba_count.

**Parameters**

``struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to update.

``uint64_t lba_count``
  Value to assign to the lba_count field.


.. c:function:: uint64_t libnvme_ns_get_lba_count (const struct libnvme_ns *p)

   Get lba_count.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

**Return**

The value of the lba_count field.


.. c:function:: void libnvme_ns_set_lba_util (struct libnvme_ns *p, uint64_t lba_util)

   Set lba_util.

**Parameters**

``struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to update.

``uint64_t lba_util``
  Value to assign to the lba_util field.


.. c:function:: uint64_t libnvme_ns_get_lba_util (const struct libnvme_ns *p)

   Get lba_util.

**Parameters**

``const struct libnvme_ns *p``
  The :c:type:`struct libnvme_ns <libnvme_ns>` instance to query.

**Return**

The value of the lba_util field.


.. c:function:: const char * libnvme_ctrl_get_name (const struct libnvme_ctrl *p)

   Get name.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the name field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_sysfs_dir (const struct libnvme_ctrl *p)

   Get sysfs_dir.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the sysfs_dir field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_firmware (const struct libnvme_ctrl *p)

   Get firmware.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the firmware field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_model (const struct libnvme_ctrl *p)

   Get model.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the model field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_numa_node (const struct libnvme_ctrl *p)

   Get numa_node.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the numa_node field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_queue_count (const struct libnvme_ctrl *p)

   Get queue_count.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the queue_count field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_serial (const struct libnvme_ctrl *p)

   Get serial.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the serial field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_sqsize (const struct libnvme_ctrl *p)

   Get sqsize.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the sqsize field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_transport (const struct libnvme_ctrl *p)

   Get transport.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the transport field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_subsysnqn (const struct libnvme_ctrl *p)

   Get subsysnqn.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the subsysnqn field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_traddr (const struct libnvme_ctrl *p)

   Get traddr.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the traddr field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_trsvcid (const struct libnvme_ctrl *p)

   Get trsvcid.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the trsvcid field, or NULL if not set.


.. c:function:: void libnvme_ctrl_set_dhchap_host_key (struct libnvme_ctrl *p, const char *dhchap_host_key)

   Set dhchap_host_key.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *dhchap_host_key``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_ctrl_get_dhchap_host_key (const struct libnvme_ctrl *p)

   Get dhchap_host_key.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the dhchap_host_key field, or NULL if not set.


.. c:function:: void libnvme_ctrl_set_dhchap_ctrl_key (struct libnvme_ctrl *p, const char *dhchap_ctrl_key)

   Set dhchap_ctrl_key.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *dhchap_ctrl_key``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_ctrl_get_dhchap_ctrl_key (const struct libnvme_ctrl *p)

   Get dhchap_ctrl_key.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the dhchap_ctrl_key field, or NULL if not set.


.. c:function:: void libnvme_ctrl_set_keyring (struct libnvme_ctrl *p, const char *keyring)

   Set keyring.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *keyring``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_ctrl_get_keyring (const struct libnvme_ctrl *p)

   Get keyring.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the keyring field, or NULL if not set.


.. c:function:: void libnvme_ctrl_set_tls_key_identity (struct libnvme_ctrl *p, const char *tls_key_identity)

   Set tls_key_identity.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *tls_key_identity``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_ctrl_get_tls_key_identity (const struct libnvme_ctrl *p)

   Get tls_key_identity.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the tls_key_identity field, or NULL if not set.


.. c:function:: void libnvme_ctrl_set_tls_key (struct libnvme_ctrl *p, const char *tls_key)

   Set tls_key.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``const char *tls_key``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_ctrl_get_tls_key (const struct libnvme_ctrl *p)

   Get tls_key.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the tls_key field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_cntrltype (const struct libnvme_ctrl *p)

   Get cntrltype.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the cntrltype field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_cntlid (const struct libnvme_ctrl *p)

   Get cntlid.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the cntlid field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_dctype (const struct libnvme_ctrl *p)

   Get dctype.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the dctype field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_phy_slot (const struct libnvme_ctrl *p)

   Get phy_slot.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the phy_slot field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_host_traddr (const struct libnvme_ctrl *p)

   Get host_traddr.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the host_traddr field, or NULL if not set.


.. c:function:: const char * libnvme_ctrl_get_host_iface (const struct libnvme_ctrl *p)

   Get host_iface.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the host_iface field, or NULL if not set.


.. c:function:: void libnvme_ctrl_set_discovery_ctrl (struct libnvme_ctrl *p, bool discovery_ctrl)

   Set discovery_ctrl.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``bool discovery_ctrl``
  Value to assign to the discovery_ctrl field.


.. c:function:: bool libnvme_ctrl_get_discovery_ctrl (const struct libnvme_ctrl *p)

   Get discovery_ctrl.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the discovery_ctrl field.


.. c:function:: void libnvme_ctrl_set_unique_discovery_ctrl (struct libnvme_ctrl *p, bool unique_discovery_ctrl)

   Set unique_discovery_ctrl.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``bool unique_discovery_ctrl``
  Value to assign to the unique_discovery_ctrl field.


.. c:function:: bool libnvme_ctrl_get_unique_discovery_ctrl (const struct libnvme_ctrl *p)

   Get unique_discovery_ctrl.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the unique_discovery_ctrl field.


.. c:function:: void libnvme_ctrl_set_discovered (struct libnvme_ctrl *p, bool discovered)

   Set discovered.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``bool discovered``
  Value to assign to the discovered field.


.. c:function:: bool libnvme_ctrl_get_discovered (const struct libnvme_ctrl *p)

   Get discovered.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the discovered field.


.. c:function:: void libnvme_ctrl_set_persistent (struct libnvme_ctrl *p, bool persistent)

   Set persistent.

**Parameters**

``struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to update.

``bool persistent``
  Value to assign to the persistent field.


.. c:function:: bool libnvme_ctrl_get_persistent (const struct libnvme_ctrl *p)

   Get persistent.

**Parameters**

``const struct libnvme_ctrl *p``
  The :c:type:`struct libnvme_ctrl <libnvme_ctrl>` instance to query.

**Return**

The value of the persistent field.


.. c:function:: const char * libnvme_subsystem_get_name (const struct libnvme_subsystem *p)

   Get name.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

**Return**

The value of the name field, or NULL if not set.


.. c:function:: const char * libnvme_subsystem_get_sysfs_dir (const struct libnvme_subsystem *p)

   Get sysfs_dir.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

**Return**

The value of the sysfs_dir field, or NULL if not set.


.. c:function:: const char * libnvme_subsystem_get_subsysnqn (const struct libnvme_subsystem *p)

   Get subsysnqn.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

**Return**

The value of the subsysnqn field, or NULL if not set.


.. c:function:: const char * libnvme_subsystem_get_model (const struct libnvme_subsystem *p)

   Get model.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

**Return**

The value of the model field, or NULL if not set.


.. c:function:: const char * libnvme_subsystem_get_serial (const struct libnvme_subsystem *p)

   Get serial.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

**Return**

The value of the serial field, or NULL if not set.


.. c:function:: const char * libnvme_subsystem_get_firmware (const struct libnvme_subsystem *p)

   Get firmware.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

**Return**

The value of the firmware field, or NULL if not set.


.. c:function:: const char * libnvme_subsystem_get_subsystype (const struct libnvme_subsystem *p)

   Get subsystype.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

**Return**

The value of the subsystype field, or NULL if not set.


.. c:function:: void libnvme_subsystem_set_application (struct libnvme_subsystem *p, const char *application)

   Set application.

**Parameters**

``struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to update.

``const char *application``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_subsystem_get_application (const struct libnvme_subsystem *p)

   Get application.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

**Return**

The value of the application field, or NULL if not set.


.. c:function:: void libnvme_subsystem_set_iopolicy (struct libnvme_subsystem *p, const char *iopolicy)

   Set iopolicy.

**Parameters**

``struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to update.

``const char *iopolicy``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_subsystem_get_iopolicy (const struct libnvme_subsystem *p)

   Get iopolicy.

**Parameters**

``const struct libnvme_subsystem *p``
  The :c:type:`struct libnvme_subsystem <libnvme_subsystem>` instance to query.

**Return**

The value of the iopolicy field, or NULL if not set.


.. c:function:: const char * libnvme_host_get_hostnqn (const struct libnvme_host *p)

   Get hostnqn.

**Parameters**

``const struct libnvme_host *p``
  The :c:type:`struct libnvme_host <libnvme_host>` instance to query.

**Return**

The value of the hostnqn field, or NULL if not set.


.. c:function:: const char * libnvme_host_get_hostid (const struct libnvme_host *p)

   Get hostid.

**Parameters**

``const struct libnvme_host *p``
  The :c:type:`struct libnvme_host <libnvme_host>` instance to query.

**Return**

The value of the hostid field, or NULL if not set.


.. c:function:: void libnvme_host_set_dhchap_host_key (struct libnvme_host *p, const char *dhchap_host_key)

   Set dhchap_host_key.

**Parameters**

``struct libnvme_host *p``
  The :c:type:`struct libnvme_host <libnvme_host>` instance to update.

``const char *dhchap_host_key``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_host_get_dhchap_host_key (const struct libnvme_host *p)

   Get dhchap_host_key.

**Parameters**

``const struct libnvme_host *p``
  The :c:type:`struct libnvme_host <libnvme_host>` instance to query.

**Return**

The value of the dhchap_host_key field, or NULL if not set.


.. c:function:: void libnvme_host_set_hostsymname (struct libnvme_host *p, const char *hostsymname)

   Set hostsymname.

**Parameters**

``struct libnvme_host *p``
  The :c:type:`struct libnvme_host <libnvme_host>` instance to update.

``const char *hostsymname``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvme_host_get_hostsymname (const struct libnvme_host *p)

   Get hostsymname.

**Parameters**

``const struct libnvme_host *p``
  The :c:type:`struct libnvme_host <libnvme_host>` instance to query.

**Return**

The value of the hostsymname field, or NULL if not set.


.. c:function:: void libnvme_host_set_pdc_enabled_valid (struct libnvme_host *p, bool pdc_enabled_valid)

   Set pdc_enabled_valid.

**Parameters**

``struct libnvme_host *p``
  The :c:type:`struct libnvme_host <libnvme_host>` instance to update.

``bool pdc_enabled_valid``
  Value to assign to the pdc_enabled_valid field.


.. c:function:: bool libnvme_host_get_pdc_enabled_valid (const struct libnvme_host *p)

   Get pdc_enabled_valid.

**Parameters**

``const struct libnvme_host *p``
  The :c:type:`struct libnvme_host <libnvme_host>` instance to query.

**Return**

The value of the pdc_enabled_valid field.


.. c:function:: void libnvme_fabric_options_set_cntlid (struct libnvme_fabric_options *p, bool cntlid)

   Set cntlid.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool cntlid``
  Value to assign to the cntlid field.


.. c:function:: bool libnvme_fabric_options_get_cntlid (const struct libnvme_fabric_options *p)

   Get cntlid.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the cntlid field.


.. c:function:: void libnvme_fabric_options_set_concat (struct libnvme_fabric_options *p, bool concat)

   Set concat.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool concat``
  Value to assign to the concat field.


.. c:function:: bool libnvme_fabric_options_get_concat (const struct libnvme_fabric_options *p)

   Get concat.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the concat field.


.. c:function:: void libnvme_fabric_options_set_ctrl_loss_tmo (struct libnvme_fabric_options *p, bool ctrl_loss_tmo)

   Set ctrl_loss_tmo.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool ctrl_loss_tmo``
  Value to assign to the ctrl_loss_tmo field.


.. c:function:: bool libnvme_fabric_options_get_ctrl_loss_tmo (const struct libnvme_fabric_options *p)

   Get ctrl_loss_tmo.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the ctrl_loss_tmo field.


.. c:function:: void libnvme_fabric_options_set_data_digest (struct libnvme_fabric_options *p, bool data_digest)

   Set data_digest.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool data_digest``
  Value to assign to the data_digest field.


.. c:function:: bool libnvme_fabric_options_get_data_digest (const struct libnvme_fabric_options *p)

   Get data_digest.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the data_digest field.


.. c:function:: void libnvme_fabric_options_set_dhchap_ctrl_secret (struct libnvme_fabric_options *p, bool dhchap_ctrl_secret)

   Set dhchap_ctrl_secret.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool dhchap_ctrl_secret``
  Value to assign to the dhchap_ctrl_secret field.


.. c:function:: bool libnvme_fabric_options_get_dhchap_ctrl_secret (const struct libnvme_fabric_options *p)

   Get dhchap_ctrl_secret.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the dhchap_ctrl_secret field.


.. c:function:: void libnvme_fabric_options_set_dhchap_secret (struct libnvme_fabric_options *p, bool dhchap_secret)

   Set dhchap_secret.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool dhchap_secret``
  Value to assign to the dhchap_secret field.


.. c:function:: bool libnvme_fabric_options_get_dhchap_secret (const struct libnvme_fabric_options *p)

   Get dhchap_secret.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the dhchap_secret field.


.. c:function:: void libnvme_fabric_options_set_disable_sqflow (struct libnvme_fabric_options *p, bool disable_sqflow)

   Set disable_sqflow.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool disable_sqflow``
  Value to assign to the disable_sqflow field.


.. c:function:: bool libnvme_fabric_options_get_disable_sqflow (const struct libnvme_fabric_options *p)

   Get disable_sqflow.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the disable_sqflow field.


.. c:function:: void libnvme_fabric_options_set_discovery (struct libnvme_fabric_options *p, bool discovery)

   Set discovery.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool discovery``
  Value to assign to the discovery field.


.. c:function:: bool libnvme_fabric_options_get_discovery (const struct libnvme_fabric_options *p)

   Get discovery.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the discovery field.


.. c:function:: void libnvme_fabric_options_set_duplicate_connect (struct libnvme_fabric_options *p, bool duplicate_connect)

   Set duplicate_connect.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool duplicate_connect``
  Value to assign to the duplicate_connect field.


.. c:function:: bool libnvme_fabric_options_get_duplicate_connect (const struct libnvme_fabric_options *p)

   Get duplicate_connect.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the duplicate_connect field.


.. c:function:: void libnvme_fabric_options_set_fast_io_fail_tmo (struct libnvme_fabric_options *p, bool fast_io_fail_tmo)

   Set fast_io_fail_tmo.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool fast_io_fail_tmo``
  Value to assign to the fast_io_fail_tmo field.


.. c:function:: bool libnvme_fabric_options_get_fast_io_fail_tmo (const struct libnvme_fabric_options *p)

   Get fast_io_fail_tmo.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the fast_io_fail_tmo field.


.. c:function:: void libnvme_fabric_options_set_hdr_digest (struct libnvme_fabric_options *p, bool hdr_digest)

   Set hdr_digest.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool hdr_digest``
  Value to assign to the hdr_digest field.


.. c:function:: bool libnvme_fabric_options_get_hdr_digest (const struct libnvme_fabric_options *p)

   Get hdr_digest.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the hdr_digest field.


.. c:function:: void libnvme_fabric_options_set_host_iface (struct libnvme_fabric_options *p, bool host_iface)

   Set host_iface.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool host_iface``
  Value to assign to the host_iface field.


.. c:function:: bool libnvme_fabric_options_get_host_iface (const struct libnvme_fabric_options *p)

   Get host_iface.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the host_iface field.


.. c:function:: void libnvme_fabric_options_set_host_traddr (struct libnvme_fabric_options *p, bool host_traddr)

   Set host_traddr.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool host_traddr``
  Value to assign to the host_traddr field.


.. c:function:: bool libnvme_fabric_options_get_host_traddr (const struct libnvme_fabric_options *p)

   Get host_traddr.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the host_traddr field.


.. c:function:: void libnvme_fabric_options_set_hostid (struct libnvme_fabric_options *p, bool hostid)

   Set hostid.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool hostid``
  Value to assign to the hostid field.


.. c:function:: bool libnvme_fabric_options_get_hostid (const struct libnvme_fabric_options *p)

   Get hostid.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the hostid field.


.. c:function:: void libnvme_fabric_options_set_hostnqn (struct libnvme_fabric_options *p, bool hostnqn)

   Set hostnqn.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool hostnqn``
  Value to assign to the hostnqn field.


.. c:function:: bool libnvme_fabric_options_get_hostnqn (const struct libnvme_fabric_options *p)

   Get hostnqn.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the hostnqn field.


.. c:function:: void libnvme_fabric_options_set_instance (struct libnvme_fabric_options *p, bool instance)

   Set instance.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool instance``
  Value to assign to the instance field.


.. c:function:: bool libnvme_fabric_options_get_instance (const struct libnvme_fabric_options *p)

   Get instance.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the instance field.


.. c:function:: void libnvme_fabric_options_set_keep_alive_tmo (struct libnvme_fabric_options *p, bool keep_alive_tmo)

   Set keep_alive_tmo.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool keep_alive_tmo``
  Value to assign to the keep_alive_tmo field.


.. c:function:: bool libnvme_fabric_options_get_keep_alive_tmo (const struct libnvme_fabric_options *p)

   Get keep_alive_tmo.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the keep_alive_tmo field.


.. c:function:: void libnvme_fabric_options_set_keyring (struct libnvme_fabric_options *p, bool keyring)

   Set keyring.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool keyring``
  Value to assign to the keyring field.


.. c:function:: bool libnvme_fabric_options_get_keyring (const struct libnvme_fabric_options *p)

   Get keyring.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the keyring field.


.. c:function:: void libnvme_fabric_options_set_nqn (struct libnvme_fabric_options *p, bool nqn)

   Set nqn.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool nqn``
  Value to assign to the nqn field.


.. c:function:: bool libnvme_fabric_options_get_nqn (const struct libnvme_fabric_options *p)

   Get nqn.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the nqn field.


.. c:function:: void libnvme_fabric_options_set_nr_io_queues (struct libnvme_fabric_options *p, bool nr_io_queues)

   Set nr_io_queues.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool nr_io_queues``
  Value to assign to the nr_io_queues field.


.. c:function:: bool libnvme_fabric_options_get_nr_io_queues (const struct libnvme_fabric_options *p)

   Get nr_io_queues.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the nr_io_queues field.


.. c:function:: void libnvme_fabric_options_set_nr_poll_queues (struct libnvme_fabric_options *p, bool nr_poll_queues)

   Set nr_poll_queues.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool nr_poll_queues``
  Value to assign to the nr_poll_queues field.


.. c:function:: bool libnvme_fabric_options_get_nr_poll_queues (const struct libnvme_fabric_options *p)

   Get nr_poll_queues.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the nr_poll_queues field.


.. c:function:: void libnvme_fabric_options_set_nr_write_queues (struct libnvme_fabric_options *p, bool nr_write_queues)

   Set nr_write_queues.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool nr_write_queues``
  Value to assign to the nr_write_queues field.


.. c:function:: bool libnvme_fabric_options_get_nr_write_queues (const struct libnvme_fabric_options *p)

   Get nr_write_queues.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the nr_write_queues field.


.. c:function:: void libnvme_fabric_options_set_queue_size (struct libnvme_fabric_options *p, bool queue_size)

   Set queue_size.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool queue_size``
  Value to assign to the queue_size field.


.. c:function:: bool libnvme_fabric_options_get_queue_size (const struct libnvme_fabric_options *p)

   Get queue_size.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the queue_size field.


.. c:function:: void libnvme_fabric_options_set_reconnect_delay (struct libnvme_fabric_options *p, bool reconnect_delay)

   Set reconnect_delay.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool reconnect_delay``
  Value to assign to the reconnect_delay field.


.. c:function:: bool libnvme_fabric_options_get_reconnect_delay (const struct libnvme_fabric_options *p)

   Get reconnect_delay.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the reconnect_delay field.


.. c:function:: void libnvme_fabric_options_set_tls (struct libnvme_fabric_options *p, bool tls)

   Set tls.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool tls``
  Value to assign to the tls field.


.. c:function:: bool libnvme_fabric_options_get_tls (const struct libnvme_fabric_options *p)

   Get tls.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the tls field.


.. c:function:: void libnvme_fabric_options_set_tls_key (struct libnvme_fabric_options *p, bool tls_key)

   Set tls_key.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool tls_key``
  Value to assign to the tls_key field.


.. c:function:: bool libnvme_fabric_options_get_tls_key (const struct libnvme_fabric_options *p)

   Get tls_key.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the tls_key field.


.. c:function:: void libnvme_fabric_options_set_tos (struct libnvme_fabric_options *p, bool tos)

   Set tos.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool tos``
  Value to assign to the tos field.


.. c:function:: bool libnvme_fabric_options_get_tos (const struct libnvme_fabric_options *p)

   Get tos.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the tos field.


.. c:function:: void libnvme_fabric_options_set_traddr (struct libnvme_fabric_options *p, bool traddr)

   Set traddr.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool traddr``
  Value to assign to the traddr field.


.. c:function:: bool libnvme_fabric_options_get_traddr (const struct libnvme_fabric_options *p)

   Get traddr.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the traddr field.


.. c:function:: void libnvme_fabric_options_set_transport (struct libnvme_fabric_options *p, bool transport)

   Set transport.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool transport``
  Value to assign to the transport field.


.. c:function:: bool libnvme_fabric_options_get_transport (const struct libnvme_fabric_options *p)

   Get transport.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the transport field.


.. c:function:: void libnvme_fabric_options_set_trsvcid (struct libnvme_fabric_options *p, bool trsvcid)

   Set trsvcid.

**Parameters**

``struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to update.

``bool trsvcid``
  Value to assign to the trsvcid field.


.. c:function:: bool libnvme_fabric_options_get_trsvcid (const struct libnvme_fabric_options *p)

   Get trsvcid.

**Parameters**

``const struct libnvme_fabric_options *p``
  The :c:type:`struct libnvme_fabric_options <libnvme_fabric_options>` instance to query.

**Return**

The value of the trsvcid field.


