#ifndef _CONN_DB_H
#define _CONN_DB_H
#include "log.h"

struct nvme_connection {
	char transport[5];
	char *traddr;
	char *trsvcid;
	char *host_traddr;

	int status;
	int discovery_pending:1;
	int did_discovery:1;
	int successful_discovery:1;
	union {
		pid_t discovery_task;
		int discovery_result;
	};
	int discovery_instance;
};

/* connection status */
enum {
	CS_NEW = 0,
	CS_DISC_RUNNING,
	CS_ONLINE,
	CS_FAILED,
	__CS_LAST,
};

/**
 * conn_status_str() - return string representation of connection status
 */
const char *conn_status_str(int status);

/**
 * conndb_add() - add a connection with given parameters
 *
 * @new_conn: if non-NULL and the function succeeds, will receive a pointer
 *            to the either existing or newly created connection object.
 *
 * Looks up the given connection parameters in the db and adds a new connection
 * unless found. All input parameters except trsvcid must be non-NULL.
 *
 * Return: 0 if controller was added, -EEXIST if controller existed in the db
 *         (this is considered success), or other negative error code in
 *         the error case.
 *
 */
int conndb_add(const char *transport, const char *traddr,
	       const char *trsvcid, const char *host_traddr,
	       struct nvme_connection **new_conn);

/**
 * conndb_add_disc_ctrl - add connection from kernel parameters
 *
 * @addrstr: kernel connect parameters as passed to /dev/nvme-fabrics
 * @new_conn: see conndb_add()
 *
 * Extracts connection parameters from @addrstr and calls conndb_add().
 *
 * Return: see conndb_add().
 */
int conndb_add_disc_ctrl(const char *addrstr, struct nvme_connection **new_conn);

/**
 * conndb_find() - lookup a connection with given parameters
 *
 * Return: NULL if not found, valid connection object otherwise.
 */
struct nvme_connection *conndb_find(const char *transport, const char *traddr,
				    const char *trsvcid, const char *host_traddr);


/**
 * conndb_find_by_pid() - lookup connection by discovery task pid
 *
 * Return: valid connetion object if successful, NULL otherwise.
 */
struct nvme_connection *conndb_find_by_pid(pid_t pid);


/**
 * conndb_find_by_pid() - lookup connection from controller instance
 *
 * Return: valid connetion object if a connection was found that has
 * the given device as discovery controller. NULL otherwise.
 */
struct nvme_connection *conndb_find_by_ctrl(const char *devname);

enum {
	CD_CB_OK    = 0,
	CD_CB_ERR   = (1 << 0),
	CD_CB_DEL   = (1 << 1),
	CD_CB_BREAK = (1 << 2),
};

/**
 *  conndb_for_each() - run a callback for each connection
 *
 * @callback: function to be called
 * @arg:      user argument passed to callback
 *
 * The callback must return a bitmask created from the CD_CB_* enum
 * values above. CD_CB_ERR signals an error condition in the callback.
 * CD_CB_DEL causes the connection to be deleted after the callback
 * returns. CD_CB_BREAK stops the iteration. Returning a value that
 * is not an OR-ed from these values is an error.
 *
 * Return: 0 if all callbacks completed successfully.
 *         A negative error code if some callback failed.
 */
int conndb_for_each(int (*callback)(struct nvme_connection *co, void *arg),
		    void *arg);

/**
 * conndb_matches - check if connection matches given parameters
 *
 * The arguments @transport and @traddr must be non-null and non-empty.
 * @trscvid and @host_traddr may be NULL, in which case they match
 * connections that don't have these attributes set, either.
 *
 * Return: true iff the given connection matches the given attributes.
 */
bool conndb_matches(const char *transport, const char *traddr,
		    const char *trsvcid, const char *host_traddr,
		    const struct nvme_connection *co);

/**
 * conndb_delete() - remove a given nvme connection object
 *
 * Removes the object from the data base and frees it.
 *
 * Return: 0 if successful, negative error code otherwise
 */
int conndb_delete(struct nvme_connection *co);

/**
 * conndb-free() - free internal data structures
 */
void conndb_free(void);

/**
 * conndb_init_from_sysfs() - check existing NVMe connections
 *
 * Populates the connection db from existing contoller devices in sysfs.
 *
 * Return: (positive or zero) number of found connections on success.
 *         Negative error code on failure.
 */
int conndb_init_from_sysfs(void);

/**
 * conn_msg() - print a log message prepended by a connection params
 * @lvl: standard syslog log level
 * @c: nvme connection to print information
 * @fmt: format string
 * ...: parameters for format
 */
void __attribute__((format(printf, 4, 5)))
_conn_msg(int lvl, const char *func, const struct nvme_connection *c,
	  const char *fmt, ...);

#define conn_msg(lvl, c, fmt, ...) \
do {									\
	if ((lvl) <= MAX_LOGLEVEL)					\
		_conn_msg(lvl, _log_func, c, fmt, ##__VA_ARGS__);	\
} while (0)

#endif
