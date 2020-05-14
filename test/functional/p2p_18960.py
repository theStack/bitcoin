#!/usr/bin/env python3
from test_framework.node_shell import NodeShell
from test_framework.mininode import P2PInterface
from test_framework.messages import (
    FILTER_TYPE_BASIC,
    msg_getcfcheckpt,
)
from test_framework.util import assert_equal
import time

# block number 630000
STOP_HASH = "000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d"

test = NodeShell()
test.setup(datadir="/home/honeybadger/.bitcoin/")
info = test.nodes[0].getnetworkinfo()
print(info)

p2p_conn = test.nodes[0].p2ps[0]

for run in range(1,100+1):
    request = msg_getcfcheckpt(
        filter_type=FILTER_TYPE_BASIC,
        stop_hash=int(STOP_HASH, 16)
    )
    start_time = time.time()
    p2p_conn.send_and_ping(message=request)
    end_time = time.time()
    response = p2p_conn.last_message['cfcheckpt']
    assert_equal(response.filter_type, request.filter_type)
    assert_equal(response.stop_hash, request.stop_hash)
    #assert_equal(len(response.headers), 1)
    print("run {}: got {} headers in {} seconds".format(run,
        len(response.headers), end_time-start_time))

test.shutdown()
