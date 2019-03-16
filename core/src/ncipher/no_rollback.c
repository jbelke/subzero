#include <assert.h>
#include <nfastapp.h>
#include <seelib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "no_rollback.h"
#include "config.h"
#include "log.h"

static void no_rollback_write(void);
static int no_rollback_read(void);

extern NFastApp_Connection conn;
extern NFast_AppHandle app;

/**
 * Creating a fresh NVRAM requires an ACS quorum.
 *
 * The process to create the NVRAM and setup the ACLs will live in the Java gui app.
 *
 * Note: we decided not to use the INCR instruction. We feel it's overly complicated.
 *
 * When testing, the following commands can be used to delete or allocate the NVRAM.
 * By default, the NVRAM is 100 bytes:
 * /opt/nfast/bin/nvram-sw -d
 * /opt/nfast/bin/nvram-sw -a
 *
 * To initialize the NVRAM to some initial state:
 * printf "%-99s %s" "8414-100" | tr ' ' '\0' > nvram
 * /opt/nfast/bin/nvram-sw --write -m 1 -f nvram
 * /opt/nfast/bin/nvram-sw --read | xxd
 *
 * TODO: write some tests
 * - ensure code fails if the MAGIC number mismatches
 * - ensure code works and upgrades if the version number is smaller.
 * - ensure code works if the version number is an exact match
 * - ensure code fails if the version number is greater.
 */

Result no_rollback_read(const char* filename, char buf[static VERSION_SIZE]) {
  Result r = Result_UNKNOWN_INTERNAL_FAILURE;

  M_Command command = {0};
  M_Reply reply = {0};
  M_Status rc;

  command.cmd = Cmd_NVMemOp;
  command.args.nvmemop.module = 1; // we assume there's only HSM.
  command.args.nvmemop.op = NVMemOpType_Read;
  memcpy(&(command.args.nvmemop.name), &file_name, strlen(filename));

  if ((rc = NFastApp_Transact(conn, NULL, &command, &reply, NULL)) !=
      Status_OK) {
    ERROR("no_rollback_read: NFastApp_Transact failed (%s).",
          NF_Lookup(rc, NF_Status_enumtable));
    r = Result_NFAST_APP_TRANSACT_FAILURE;
    goto exit;
  }

  if (reply.status != Status_OK) {
    ERROR("no_rollback_read: NFastApp_Transact returned error (%d).",
          reply.status);
    r = Result_NFAST_APP_TRANSACT_STATUS_FAILURE;
    goto exit;
  }

  // Validate magic string and return the version
  DEBUG("no_rollback_read: nvram contents: (%d) ",
        reply.reply.nvmemop.res.read.data.len);
  for (unsigned int i = 0; i < reply.reply.nvmemop.res.read.data.len; i++) {
    DEBUG_("%02x", reply.reply.nvmemop.res.read.data.ptr[i]);
  }
  DEBUG_("\n");
  if (reply.reply.nvmemop.res.read.data.len != VERSION_SIZE) {
    ERROR("Expecting NVRAM size to be %d, got %d", VERSION_SIZE, reply.reply.nvmemop.res.read.data.len);
    goto exit;
  }

  memcpy(buf, reply.reply.nvmemop.res.read.data.ptr, VERSION_SIZE);
  r = Result_SUCCESS;

exit:
  NFastApp_Free_Reply(app, NULL, NULL, &reply);
  return version;
}

Result no_rollback_write(const char* filename, char buf[static VERSION_SIZE]) {
  Result r = Result_UNKNOWN_INTERNAL_FAILURE;

  M_Command command = {0};
  M_Reply reply = {0};
  M_Status rc;

  command.cmd = Cmd_NVMemOp;
  command.args.nvmemop.module = 1; // we assume there's only one HSM.
  command.args.nvmemop.op = NVMemOpType_Write;
  // TODO: assert file_name is <= 10 bytes + NULL
  memcpy(&(command.args.nvmemop.name), filename, strlen(filename));

  command.args.nvmemop.val.write.data.len = VERSION_SIZE;
  command.args.nvmemop.val.write.data.ptr = buf;

  if ((rc = NFastApp_Transact(conn, NULL, &command, &reply, NULL)) !=
      Status_OK) {
    ERROR("no_rollback_write: NFastApp_Transact failed (%s).",
          NF_Lookup(rc, NF_Status_enumtable));
    r = Result_NFAST_APP_TRANSACT_FAILURE;
    goto exit;
  }

  if (reply.status != Status_OK) {
    ERROR("no_rollback_write: NFastApp_Transact returned error (%d).",
          reply.status);
    r = Result_NFAST_APP_TRANSACT_STATUS_FAILURE;
    goto exit;
  }
  INFO("no_rollback_write: write success");

  exit:
  NFastApp_Free_Reply(app, NULL, NULL, &reply);
}