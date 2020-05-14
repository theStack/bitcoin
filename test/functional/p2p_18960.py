#!/usr/bin/env python3
from test_framework.node_shell import NodeShell
from test_framework.mininode import P2PInterface
from test_framework.messages import (
    FILTER_TYPE_BASIC,
    msg_getcfcheckpt,
)
from test_framework.util import assert_equal
import os, time

STOP_BLOCK_HEIGHT = 630000
NUMBER_OF_RUNS = 100

test = NodeShell()
test.setup(datadir= os.getenv("HOME") + "/.bitcoin/")
stop_hash = test.nodes[0].getblockhash(STOP_BLOCK_HEIGHT)
p2p_conn = test.nodes[0].p2ps[0]

request = msg_getcfcheckpt(
    filter_type=FILTER_TYPE_BASIC,
    stop_hash=int(stop_hash, 16)
)

first_processing_time = None
following_processing_times = []

for run in range(1,NUMBER_OF_RUNS+1):
    start_time = time.time()
    p2p_conn.send_and_ping(message=request)
    processing_time = time.time() - start_time

    response = p2p_conn.last_message['cfcheckpt']
    assert_equal(response.filter_type, request.filter_type)
    assert_equal(response.stop_hash, request.stop_hash)
    assert_equal(len(response.headers), STOP_BLOCK_HEIGHT//1000)

    print("run {}: got {} headers in {} ms".format(run,
        len(response.headers), processing_time*1000))
    if run == 1:
        first_processing_time = processing_time
    else:
        following_processing_times.append(processing_time)

print("getcfcheckpt request processing times")
print("=====================================")
print("-> first:     {:.2f}ms".format(first_processing_time*1000))
average_processing_time = sum(following_processing_times)/len(following_processing_times)
print("-> following: {:.2f}ms (average)".format(average_processing_time*1000))
print("=====================================")

test.shutdown()
