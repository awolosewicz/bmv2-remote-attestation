/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

/* Switch instance */

#include <bm/config.h>

#include <bm/SimpleSwitch.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/options_parse.h>
#include <bm/bm_sim/target_parser.h>

#include "simple_switch.h"

namespace {
SimpleSwitch *simple_switch;
}  // namespace

namespace sswitch_runtime {
shared_ptr<SimpleSwitchIf> get_handler(SimpleSwitch *sw);
}  // namespace sswitch_runtime

int
main(int argc, char* argv[]) {
  bm::TargetParserBasicWithDynModules simple_switch_parser;
  simple_switch_parser.add_flag_option(
      "enable-swap",
      "Enable JSON swapping at runtime");
  simple_switch_parser.add_uint_option(
      "drop-port",
      "Choose drop port number (default is 511)");
  simple_switch_parser.add_flag_option(
      "enable-spade",
      "Enable writing to SPADE pipe");
  simple_switch_parser.add_string_option(
      "spade-file",
      "The file to write provenance information to (default is spade_pipe). Requires --enable-spade");
  simple_switch_parser.add_uint_option(
      "spade-switch-id",
      "Choose id for this switch, 1-20 (default 1). All vertices from this switch will have IDs of [switch][packet][clone].\n"
      "Switch is 1-20 inclusive (0 reserved), packet is 1-(10M-1), clone is 2-9 (parent in is 0, out is 1).\n"
      "EX: Clone 2 of packet 192 of switch 4 is 0400001922.");
  simple_switch_parser.add_uint_option(
      "spade-verbosity",
      "The level of verbosity of traffic recorded to SPADE (default 0)\n"
      "0: Capture every packet alongside size and ethertype\n"
      "1: Capture only unique flows from input to output (or drop) ports\n"
      "2: 0, but additionally include IPv4 and IPv6 addresses and protocols for those packets\n"
      "3: Capture unique flows based off source and destination IPv4/IPv6 addresses\n"
      "4: 3, but also unique based off TCP/UDP source and destination ports");
  simple_switch_parser.add_uint_option(
      "spade-period",
      "The length of the polling period in ms where, for verbosity options that capture unique flows,\n"
      "duplicate flows will be recorded. For example, a value of 5000 means duplicate flows will be recorded\n"
      "every 5s as long as the flow occurs within the 5s window (default 10000). 0 captures all flows.");
  simple_switch_parser.add_flag_option(
      "disable-ra-broadcast",
      "Disables the ethernet broadcast of RA evidence.");

  bm::OptionsParser parser;
  parser.parse(argc, argv, &simple_switch_parser);

  bool enable_swap_flag = false;
  if (simple_switch_parser.get_flag_option("enable-swap", &enable_swap_flag)
      != bm::TargetParserBasic::ReturnCode::SUCCESS) {
    std::exit(1);
  }

  uint32_t drop_port = 0xffffffff;
  {
    auto rc = simple_switch_parser.get_uint_option("drop-port", &drop_port);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      drop_port = SimpleSwitch::default_drop_port;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  bool enable_spade_flag = false;
  if (simple_switch_parser.get_flag_option("enable-spade", &enable_spade_flag)
      != bm::TargetParserBasic::ReturnCode::SUCCESS) {
    std::exit(1);
  }
  
  std::string spade_file = "";
  if (enable_spade_flag) {
    {
      auto rc = simple_switch_parser.get_string_option("spade-file", &spade_file);
      if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
        spade_file = "spade_pipe";
      else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
        std::exit(1);
    }
  }
  
  uint32_t spade_switch_id = 0xffffffff;
  {
    auto rc = simple_switch_parser.get_uint_option("spade-switch-id", &spade_switch_id);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      spade_switch_id = SimpleSwitch::default_spade_id;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
    spade_switch_id *= SPADE_SWITCH_ID_MULT; // 100M
  }
  
  uint32_t spade_verbosity = 0xffffffff;
  {
    auto rc = simple_switch_parser.get_uint_option("spade-verbosity", &spade_verbosity);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      spade_verbosity = SimpleSwitch::default_spade_verbosity;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }
  
  uint32_t spade_period = 0xffffffff;
  {
    auto rc = simple_switch_parser.get_uint_option("spade-period", &spade_period);
    if (rc == bm::TargetParserBasic::ReturnCode::OPTION_NOT_PROVIDED)
      spade_period = SimpleSwitch::default_spade_period;
    else if (rc != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
  }

  bool disable_ra_broadcast_flag = false;
  if (simple_switch_parser.get_flag_option("disable-ra-broadcast", &disable_ra_broadcast_flag)
      != bm::TargetParserBasic::ReturnCode::SUCCESS) {
    std::exit(1);
  }

  simple_switch = new SimpleSwitch(enable_swap_flag, drop_port, enable_spade_flag, spade_file, spade_switch_id,
                                   spade_verbosity, spade_period, disable_ra_broadcast_flag);
  int status = simple_switch->init_from_options_parser(parser);
  if (status != 0) std::exit(status);
  if (enable_spade_flag){
    int spade_status = simple_switch->spade_setup_ports();
    if (spade_status != 0) std::exit(1);
  }

  int thrift_port = simple_switch->get_runtime_port();
  bm_runtime::start_server(simple_switch, thrift_port);
  using ::sswitch_runtime::SimpleSwitchIf;
  using ::sswitch_runtime::SimpleSwitchProcessor;
  bm_runtime::add_service<SimpleSwitchIf, SimpleSwitchProcessor>(
      "simple_switch", sswitch_runtime::get_handler(simple_switch));
  simple_switch->start_and_return();

  while (true) std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
