include "config.h"
#include <epan/packet.h>

#define tsdb_PORT 1234

static int proto_tsdb = -1;

//Wireshark will call dissect_tsdb() when it receives UDP traffic on port 1234.

static int
dissect_tsdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "tsdb");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    return tvb_captured_length(tvb);
}

//Each protocol must have a register function with the form "proto_register_XXX". This function is used to register the protocol in Wireshark. The code to call the register routines is generated automatically and is called when Wireshark starts. In this example, the function is named proto_register_tsdb.

void
proto_register_tsdb(void)
{
    proto_tsdb = proto_register_protocol (
        "tsdb Protocol", /* name        */
        "tsdb",          /* short_name  */
        "tsdb"           /* filter_name */
        );
}

//proto_register_tsdb calls proto_register_protocol(), which takes a name, short name, and filter_name. 

void
proto_reg_handoff_tsdb(void)
{
    static dissector_handle_t tsdb_handle;

    tsdb_handle = create_dissector_handle(dissect_tsdb, proto_tsdb);
    dissector_add_uint("udp.port", tsdb_PORT, tsdb_handle);
}
static int
dissect_tsdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)

{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "tsdb");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    return tvb_captured_length(tvb);
}

void
proto_register_tsdb(void)
{
    proto_tsdb = proto_register_protocol (
        "tsdb Protocol", /* name        */
        "tsdb",          /* short_name  */
        "tsdb"           /* filter_name */
        );
}

void
proto_reg_handoff_tsdb(void)
{
    static dissector_handle_t tsdb_handle;

    tsdb_handle = create_dissector_handle(dissect_tsdb, proto_tsdb);
    dissector_add_uint("udp.port", tsdb_PORT, tsdb_handle);
}
