#!/usr/bin/env python3
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

import runtime_CLI
from runtime_CLI import UIn_Error
import hashlib
import time

from functools import wraps
import os
import sys

from sswitch_runtime import SimpleSwitch
from sswitch_runtime.ttypes import *

def handle_bad_input(f):
    @wraps(f)
    @runtime_CLI.handle_bad_input
    def handle(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except InvalidMirroringOperation as e:
            error = MirroringOperationErrorCode._VALUES_TO_NAMES[e.code]
            print("Invalid mirroring operation (%s)" % error)
    return handle


class Spade:
    # def __new__(enabled, file, switch_id):
    #     if not enabled:
    #         return None
        
    def __init__(self, enabled=True, file="/home/Shared/spade_pipe", CLI_id=1000000):
        self.enabled = enabled
        self.file = file
        self.CLI_id = CLI_id
        self.switch_id = CLI_id // 1000000
        self.r_id = CLI_id + 1
        self.t_id = CLI_id + 2
        self.p_id = CLI_id + 3
        self.b_id = CLI_id + 4
        self.nextuid = CLI_id + 5
        # if enabled:
        #     spade_pipe = open(file, 'a')
        #     spade_pipe.write(f"type:Process id:{self.CLI_id} subtype:CLI\n")
        #     spade_pipe.write(f"type:Artifact id:{self.r_id} subtype:CLI_reg\n")
        #     spade_pipe.write(f"type:Artifact id:{self.t_id} subtype:CLI_tbl\n")
        #     spade_pipe.write(f"type:Artifact id:{self.p_id} subtype:CLI_prog\n")
        #     spade_pipe.write(f"type:Artifact id:{self.b_id} subtype:CLI_loaded_prog\n")
        #     spade_pipe.close()

    def send_edge(self, type, from_uid, to_uid, vals):
        if not self.enabled:
            return
        spade_pipe = open(self.file, 'a')
        print(f"\nSending Edge type:{type} from:{from_uid} to:{to_uid} time:{time.time_ns()//1000} {vals}")
        spade_pipe.write(f"type:{type} from:{from_uid} to:{to_uid} time:{time.time_ns()//1000} {vals}\n")
        spade_pipe.close()

class SimpleSwitchAPI(runtime_CLI.RuntimeAPI):
    @staticmethod
    def get_thrift_services():
        return [("simple_switch", SimpleSwitch.Client)]

    def __init__(self, pre_type, standard_client, mc_client, sswitch_client):
        runtime_CLI.RuntimeAPI.__init__(self, pre_type,
                                        standard_client, mc_client)
        self.sswitch_client = sswitch_client
        self.spade = Spade(self.sswitch_client.get_spade_enabled(), self.sswitch_client.get_spade_file(), self.sswitch_client.get_spade_cli_id())

    # Modified to write a SPADE edge
    @handle_bad_input
    def do_table_clear(self, line):
        cmd_in = line.replace(" ", "\\ ")
        cmd_in = "command:table_clear\\ "+cmd_in
        self.spade.send_edge("WasGeneratedBy", self.spade.t_id, self.spade.CLI_id, cmd_in)
        runtime_CLI.RuntimeAPI.do_table_clear(self, line)
    
    # Modified to write a SPADE edge
    @handle_bad_input
    def do_table_add(self, line):
        cmd_in = line.replace(" ", "\\ ")
        cmd_in = "command:table_add\\ "+cmd_in
        self.spade.send_edge("WasGeneratedBy", self.spade.t_id, self.spade.CLI_id, cmd_in)
        runtime_CLI.RuntimeAPI.do_table_add(self, line)

    # Modified to write a SPADE edge
    @handle_bad_input
    def do_table_modify(self, line):
        cmd_in = line.replace(" ", "\\ ")
        cmd_in = "command:table_modify\\ "+cmd_in
        self.spade.send_edge("WasGeneratedBy", self.spade.t_id, self.spade.CLI_id, cmd_in)
        runtime_CLI.RuntimeAPI.do_table_modify(self, line)

    # Modified to write a SPADE edge
    @handle_bad_input
    def do_table_delete(self, line):
        cmd_in = line.replace(" ", "\\ ")
        cmd_in = "command:table_delete\\ "+cmd_in
        self.spade.send_edge("WasGeneratedBy", self.spade.t_id, self.spade.CLI_id, cmd_in)
        runtime_CLI.RuntimeAPI.do_table_delete(self, line)

    # Modified to add SPADE edge indicating program loaded to switch buffer, with MD5 of the JSON
    @handle_bad_input
    def do_load_new_config_file(self, line):
        "Load new json config: load_new_config_file <path to .json file>"
        args = line.split()
        self.exactly_n_args(args, 1)
        filename = args[0]
        if not os.path.isfile(filename):
            raise UIn_Error("Not a valid filename")
        cmd_in = line.replace(" ", "\\ ")
        cmd_in = "command:load_new_config_file\\ "+cmd_in
        # Using second read loop to reset pointer
        with open(filename, 'r') as f:
            # Reusing from bmpy_utils:check_JSON_md5
            # Changed formating to :0X (to match BMv2 side), ord(c) to c due to error
            m = hashlib.md5()
            for L in f:
                m.update(L.encode())
            md5sum = m.digest()
            md5sum_str = "".join("{:0X}".format(c) for c in md5sum)
            cmd_in  = cmd_in + " MD5:0x" + md5sum_str
            self.spade.send_edge("Used", self.spade.CLI_id, self.spade.b_id, cmd_in)
            f.close()
        runtime_CLI.RuntimeAPI.do_load_new_config_file(self, line)

    # Modified to add SPADE edges indicating the program was swapped
    @handle_bad_input
    def do_swap_configs(self, line):
        self.spade.send_edge("WasGeneratedBy", self.spade.p_id, self.spade.CLI_id, "command:swap_configs")
        self.spade.send_edge("WasDerivedFrom", self.spade.p_id, self.spade.b_id, "")
        runtime_CLI.RuntimeAPI.do_swap_configs(self, line)

    # Modified to write a SPADE edge
    @handle_bad_input
    def do_register_write(self, line):
        cmd_in = line.replace(" ", "\\ ")
        cmd_in = "command:register_write\\ "+cmd_in
        self.spade.send_edge("WasGeneratedBy", self.spade.r_id, self.spade.CLI_id, cmd_in)
        runtime_CLI.RuntimeAPI.do_register_write(self, line)

    # Modified to write a SPADE edge
    @handle_bad_input
    def do_register_reset(self, line):
        cmd_in = line.replace(" ", "\\ ")
        cmd_in = "command:register_reset\\ "+cmd_in
        self.spade.send_edge("WasGeneratedBy", self.spade.r_id, self.spade.CLI_id, cmd_in)
        runtime_CLI.RuntimeAPI.do_register_reset(self, line)

    @handle_bad_input
    def do_set_queue_depth(self, line):
        "Set depth of one / all egress queue(s): set_queue_depth <nb_pkts> [<egress_port>]"
        args = line.split()
        self.at_least_n_args(args, 1)
        depth = self.parse_int(args[0], "nb_pkts")
        if len(args) > 1:
            port = self.parse_int(args[1], "egress_port")
            self.sswitch_client.set_egress_queue_depth(port, depth)
        else:
            self.sswitch_client.set_all_egress_queue_depths(depth)

    @handle_bad_input
    def do_set_queue_rate(self, line):
        "Set rate of one / all egress queue(s): set_queue_rate <rate_pps> [<egress_port>]"
        args = line.split()
        self.at_least_n_args(args, 1)
        rate = self.parse_int(args[0], "rate_pps")
        if len(args) > 1:
            port = self.parse_int(args[1], "egress_port")
            self.sswitch_client.set_egress_queue_rate(port, rate)
        else:
            self.sswitch_client.set_all_egress_queue_rates(rate)

    @handle_bad_input
    def do_mirroring_add(self, line):
        "Add mirroring session to unicast port: mirroring_add <mirror_id> <egress_port>"
        args = line.split()
        self.exactly_n_args(args, 2)
        mirror_id = self.parse_int(args[0], "mirror_id")
        egress_port = self.parse_int(args[1], "egress_port")
        config = MirroringSessionConfig(port=egress_port)
        self.sswitch_client.mirroring_session_add(mirror_id, config)

    @handle_bad_input
    def do_mirroring_add_mc(self, line):
        "Add mirroring session to multicast group: mirroring_add_mc <mirror_id> <mgrp>"
        args = line.split()
        self.exactly_n_args(args, 2)
        mirror_id = self.parse_int(args[0], "mirror_id")
        mgrp = self.parse_int(args[1], "mgrp")
        config = MirroringSessionConfig(mgid=mgrp)
        self.sswitch_client.mirroring_session_add(mirror_id, config)

    @handle_bad_input
    def do_mirroring_delete(self, line):
        "Delete mirroring session: mirroring_delete <mirror_id>"
        args = line.split()
        self.exactly_n_args(args, 1)
        mirror_id = self.parse_int(args[0], "mirror_id")
        self.sswitch_client.mirroring_session_delete(mirror_id)

    @handle_bad_input
    def do_mirroring_get(self, line):
        "Display mirroring session: mirroring_get <mirror_id>"
        args = line.split()
        self.exactly_n_args(args, 1)
        mirror_id = self.parse_int(args[0], "mirror_id")
        config = self.sswitch_client.mirroring_session_get(mirror_id)
        print(config)

    @handle_bad_input
    def do_get_time_elapsed(self, line):
        "Get time elapsed (in microseconds) since the switch started: get_time_elapsed"
        print(self.sswitch_client.get_time_elapsed_us())

    @handle_bad_input
    def do_get_time_since_epoch(self, line):
        "Get time elapsed (in microseconds) since the switch clock's epoch: get_time_since_epoch"
        print(self.sswitch_client.get_time_since_epoch_us())

def main():
    args = runtime_CLI.get_parser().parse_args()

    args.pre = runtime_CLI.PreType.SimplePreLAG

    services = runtime_CLI.RuntimeAPI.get_thrift_services(args.pre)
    services.extend(SimpleSwitchAPI.get_thrift_services())

    standard_client, mc_client, sswitch_client = runtime_CLI.thrift_connect(
        args.thrift_ip, args.thrift_port, services
    )

    runtime_CLI.load_json_config(standard_client, args.json)

    SimpleSwitchAPI(args.pre, standard_client, mc_client, sswitch_client).cmdloop()

if __name__ == '__main__':
    main()
