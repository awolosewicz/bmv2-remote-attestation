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

#ifndef SIMPLE_SWITCH_SIMPLE_SWITCH_H_
#define SIMPLE_SWITCH_SIMPLE_SWITCH_H_

#include <bm/bm_sim/queue.h>
#include <bm/bm_sim/queueing.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/switch.h>
#include <bm/bm_sim/event_logger.h>
#include <bm/bm_sim/simple_pre_lag.h>
#include <src/bm_sim/md5.h>
#include <src/bm_sim/utils.h>

#include <memory>
#include <chrono>
#include <thread>
#include <vector>
#include <functional>

// TODO(antonin)
// experimental support for priority queueing
// to enable it, uncomment this flag
// you can also choose the field from which the priority value will be read, as
// well as the number of priority queues per port
// PRIORITY 0 IS THE LOWEST PRIORITY
// #define SSWITCH_PRIORITY_QUEUEING_ON

#ifdef SSWITCH_PRIORITY_QUEUEING_ON
#define SSWITCH_PRIORITY_QUEUEING_NB_QUEUES 8
#define SSWITCH_PRIORITY_QUEUEING_SRC "intrinsic_metadata.priority"
#endif

#define SPADE_VTYPE_AGENT 1
#define SPADE_VTYPE_PROCESS 2
#define SPADE_VTYPE_ARTIFACT 3

#define SPADE_ETYPE_USED 1
#define SPADE_ETYPE_GENERATEDBY 2
#define SPADE_ETYPE_TRIGGEREDBY 3
#define SPADE_ETYPE_DERIVEDFROM 4
#define SPADE_ETYPE_CONTROLLEDBY 5

using ts_res = std::chrono::microseconds;
using std::chrono::duration_cast;
using ticks = std::chrono::nanoseconds;
using spade_uid_t = uint32_t;
#define SPADE_UID_MAX 0xffffffff

using bm::Switch;
using bm::Context;
using bm::Queue;
using bm::Packet;
using bm::PHV;
using bm::Parser;
using bm::Deparser;
using bm::Pipeline;
using bm::McSimplePreLAG;
using bm::Field;
using bm::FieldList;
using bm::packet_id_t;
using bm::p4object_id_t;
using bm::cxt_id_t;
using bm::Data;
using bm::ActionData;
using bm::MatchTable;
using bm::MatchEntry;
using bm::MatchErrorCode;
using bm::MatchKeyParam;
using bm::entry_handle_t;

class HashList {
 public:
  std::unordered_map<std::string, unsigned char*> map{};
  unsigned char total_hash[16] = {0};
  
  void update(std::string nkey, unsigned char* nhash) {
    auto it = map.find(nkey);
    if (it == map.end()) {
      unsigned char *shash = (unsigned char*)malloc(16);
      memcpy(shash, nhash, 16);
      map.insert({nkey, shash});
      for (int i = 0; i < 16; ++i) {
        total_hash[i] += nhash[i];
      }
    }
    else {
      for (int i = 0; i < 16; ++i) {
        total_hash[i] -= it->second[i];
        total_hash[i] += nhash[i];
      }
      memcpy(it->second, nhash, 16);
    }
  }
};

class SimpleSwitch : public Switch {
 public:
  using mirror_id_t = int;

  using TransmitFn = std::function<void(port_t, packet_id_t,
                                        const char *, int)>;

  struct MirroringSessionConfig {
    port_t egress_port;
    bool egress_port_valid;
    unsigned int mgid;
    bool mgid_valid;
  };

  static constexpr port_t default_drop_port = 511;
  static constexpr uint32_t default_spade_id = 0;
  std::string loaded_config;
  spade_uid_t spade_prev_prog = 0;
  std::map<bm::DevMgrIface::port_t, spade_uid_t> spade_port_in_ids {};
  std::map<bm::DevMgrIface::port_t, spade_uid_t> spade_port_out_ids {};
  std::unordered_map<std::string, spade_uid_t> spade_register_ids {};
  std::unordered_map<std::string, spade_uid_t> spade_table_ids {};

 private:
  using clock = std::chrono::high_resolution_clock;
  mutable boost::shared_mutex spade_mutex{};

  // Remote Attestation registers
  static constexpr size_t nb_ra_registers = 3;
  unsigned char ra_registers[16*nb_ra_registers];
  mutable boost::shared_mutex ra_reg_mutex{};
  mutable boost::shared_mutex ra_tbl_mutex{};
  mutable boost::shared_mutex ra_prog_mutex{};

 public:
  // by default, swapping is off
  explicit SimpleSwitch(bool enable_swap = false,
                        port_t drop_port = default_drop_port,
                        bool enable_spade = false,
                        std::string spade_file = "spade_pipe",
                        uint32_t spade_switch_id = default_spade_id);

  ~SimpleSwitch();

  int receive_(port_t port_num, const char *buffer, int len) override;

  void start_and_return_() override;

  void reset_target_state_() override;

  void swap_notify_() override;

  bool mirroring_add_session(mirror_id_t mirror_id,
                             const MirroringSessionConfig &config);

  bool mirroring_delete_session(mirror_id_t mirror_id);

  bool mirroring_get_session(mirror_id_t mirror_id,
                             MirroringSessionConfig *config) const;

  int set_egress_queue_depth(size_t port, const size_t depth_pkts);
  int set_all_egress_queue_depths(const size_t depth_pkts);

  int set_egress_queue_rate(size_t port, const uint64_t rate_pps);
  int set_all_egress_queue_rates(const uint64_t rate_pps);

  unsigned short get_packet_etype(bm::Packet* packet);

  // returns the number of microseconds elapsed since the switch started
  uint64_t get_time_elapsed_us() const;

  // returns the number of microseconds elasped since the clock's epoch
  uint64_t get_time_since_epoch_us() const;

  // returns the packet id of most recently received packet. Not thread-safe.
  static packet_id_t get_packet_id() {
    return packet_id - 1;
  }

  void set_transmit_fn(TransmitFn fn);

  port_t get_drop_port() const {
    return drop_port;
  }

  std::string get_spade_file() const {
    return spade_file;
  }

  bool get_enable_spade() const {
    return enable_spade;
  }

  spade_uid_t spade_send_vertex(int type, spade_uit_t spade_uid, std::string vals);
  spade_uid_t spade_send_edge(int type, spade_uid_t from, spade_uid_t to, std::string vals);
  int spade_setup_ports();

  // RA Register Access
  void set_ra_registers(unsigned char *val, unsigned int idx);
  unsigned char* get_ra_register(unsigned int idx);
  HashList registers_ra;
  HashList tables_ra;

  // Get MD5 of register through hashing all the register elements
  // Uses binary representation of Data to avoid unknown of using Data directly
  void ra_update_reghash(cxt_id_t cxt_id, const std::string &register_name, std::string &spade_str) {
    boost::unique_lock<boost::shared_mutex> lock(ra_reg_mutex);
    MD5_CTX reg_md5_ctx;
    MD5_Init(&reg_md5_ctx);
    std::vector<Data> register_array = register_read_all(cxt_id, register_name);
    for (auto it = register_array.begin(); it != register_array.end(); ++it) {
      std::string reg_str = it->get_string();
      MD5_Update(&reg_md5_ctx, reg_str.data(), reg_str.size());
    }
    unsigned char reg_md5[16];
    MD5_Final(reg_md5, &reg_md5_ctx);
    registers_ra.update(register_name, reg_md5);
    set_ra_registers(registers_ra.total_hash, 0);

    std::stringstream hash_ss;
    hash_ss << "0x" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex;
    for (int i = 0; i < 16; ++i) {
      hash_ss << (int)reg_md5[i];
    }
    auto it = spade_register_ids.find(register_name);
    if (it == spade_register_ids.end()) {
      spade_uid_t register_uid = spade_send_vertex(SPADE_VTYPE_ARTIFACT, 
                                                "subtype:register register:"+register_name+" MD5:"+hash_ss.str());
      spade_register_ids.insert({register_name, register_uid});
    }
    else {
      spade_uid_t cur_register_uid = spade_send_vertex(SPADE_VTYPE_ARTIFACT, 
                                                    "subtype:register register:"+register_name+" MD5::"+hash_ss.str());
      spade_uid_t prev_register_uid = it->second;
      spade_send_edge(SPADE_ETYPE_DERIVEDFROM, cur_register_uid, prev_register_uid, spade_str);
      it->second = cur_register_uid;
    }
  }

  // Get MD5 of tables through hashing all the entries
  // An entry, in this case, is the match key(s), associated function, and function data
  void ra_update_tblhash(cxt_id_t cxt_id, const std::string &table_name, std::string &spade_str) {
    boost::unique_lock<boost::shared_mutex> lock(ra_tbl_mutex);
    MD5_CTX tbl_md5_ctx;
    MD5_Init(&tbl_md5_ctx);
    std::vector<MatchTable::Entry> tbl_entries = mt_get_entries(cxt_id, table_name);
    for (auto it = tbl_entries.begin(); it != tbl_entries.end(); ++it) {
      // Match Key
      std::vector<bm::MatchKeyParam> mt_key = it->match_key;
      for (auto it_key = mt_key.begin(); it_key != mt_key.end(); ++it_key) {
        MD5_Update(&tbl_md5_ctx, it_key->key.data(), it_key->key.size());
        MD5_Update(&tbl_md5_ctx, it_key->mask.data(), it_key->mask.size());
      }
      // Action Data
      bm::ActionData act_data = it->action_data;
      for (size_t q = 0; q < act_data.size(); ++q) {
        std::string act_str = act_data.get(q).get_string();
        MD5_Update(&tbl_md5_ctx, act_str.data(), act_str.size());
      }
      // Action Fn
      const bm::ActionFn* act_func = it->action_fn;
      MD5_Update(&tbl_md5_ctx, act_func->get_name().data(), act_func->get_name().size());
    }
    unsigned char tbl_md5[16];
    MD5_Final(tbl_md5, &tbl_md5_ctx);
    tables_ra.update(table_name, tbl_md5);
    set_ra_registers(tables_ra.total_hash, 1);

    std::stringstream hash_ss;
    hash_ss << "0x" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex;
    for (int i = 0; i < 16; ++i) {
      hash_ss << (int)tbl_md5[i];
    }
    auto it = spade_table_ids.find(table_name);
    if (it == spade_table_ids.end()) {
      spade_uid_t table_uid = spade_send_vertex(SPADE_VTYPE_ARTIFACT, 
                                                "subtype:table table:"+table_name+" MD5:"+hash_ss.str()+" "+spade_str);
      spade_table_ids.insert({table_name, table_uid});
    }
    else {
      spade_uid_t cur_table_uid = spade_send_vertex(SPADE_VTYPE_ARTIFACT, 
                                                    "subtype:table table:"+table_name+" MD5:"+hash_ss.str());
      spade_uid_t prev_table_uid = it->second;
      spade_send_edge(SPADE_ETYPE_DERIVEDFROM, cur_table_uid, prev_table_uid, spade_str);
      it->second = cur_table_uid;
    }
  }

  void ra_update_proghash() {
    boost::unique_lock<boost::shared_mutex> lock(ra_prog_mutex);
    MD5_CTX prog_md5_ctx;
    MD5_Init(&prog_md5_ctx);
    std::string current_config = get_config();
    MD5_Update(&prog_md5_ctx, current_config.data(), current_config.size());
    unsigned char prog_md5[16];
    MD5_Final(prog_md5, &prog_md5_ctx);
    set_ra_registers(prog_md5, 2);

    std::stringstream hash_ss;
    hash_ss << "0x" << std::uppercase << std::setfill('0') << std::setw(2) << std::hex;
    for (int i = 0; i < 16; ++i) {
      hash_ss << (int)prog_md5[i];
    }
    if (spade_prev_prog == 0) {
      spade_prev_prog = spade_send_vertex(SPADE_VTYPE_ARTIFACT, "subtype:program MD5:"+hash_ss.str());
    }
    else {
      spade_uid_t spade_cur_prog = spade_send_vertex(SPADE_VTYPE_ARTIFACT, "subtype:program MD5:"+hash_ss.str());
      spade_send_edge(SPADE_ETYPE_DERIVEDFROM, spade_cur_prog, spade_prev_prog, "command:swap_configs");
      spade_prev_prog = spade_cur_prog;
    }
  }

  // Hook Register/Table/Program modifying functions so they update the hashes post-update
  RegisterErrorCode
  register_write(cxt_id_t cxt_id,
                 const std::string &register_name,
                 const size_t idx, Data value) {
    auto retval = Switch::register_write(cxt_id, register_name, idx, value);
    // register_write <register_name> <idx> <value>
    std::stringstream spade_ss;
    spade_ss <<  "command:register_write\\ " << register_name << "\\ " << idx << "\\ ";
    bm::utils::dump_hexstring(spade_ss, value.get_string());
    std::string spade_str = spade_ss.str();
    ra_update_reghash(cxt_id, register_name, spade_str);
    return retval;
  }

  RegisterErrorCode
  register_write_range(cxt_id_t cxt_id,
                       const std::string &register_name,
                       const size_t start, const size_t end,
                       Data value) override {
    auto retval = Switch::register_write_range(cxt_id,
        register_name, start, end, std::move(value));
    // register_write_rangfe <register_name> <start> <end> <value>
    std::stringstream spade_ss;
    spade_ss <<  "command:register_write\\ " << register_name << "\\ " << start << "\\ " << end << "\\ ";
    bm::utils::dump_hexstring(spade_ss, value.get_string());
    std::string spade_str = spade_ss.str();
    ra_update_reghash(cxt_id, register_name, spade_str);
    return retval;
  }

  RegisterErrorCode
  register_reset(cxt_id_t cxt_id, const std::string &register_name) override {
    auto retval = Switch::register_reset(cxt_id, register_name);
    // register_reset <register_name>
    std::string spade_str = "command:register_reset\\ " + register_name;
    ra_update_reghash(cxt_id, register_name, spade_str);
    return retval;
  }

  MatchErrorCode
  mt_clear_entries(cxt_id_t cxt_id,
                    const std::string &table_name,
                    bool reset_default_entry) {
    auto retval = Switch::mt_clear_entries(cxt_id, table_name, reset_default_entry);
    // table_clear <table_name>
    std::string spade_str = "command:table_clear\\ " + table_name;
    ra_update_tblhash(cxt_id, table_name, spade_str);
    return retval;
  }

  MatchErrorCode
  mt_add_entry(cxt_id_t cxt_id,
               const std::string &table_name,
               const std::vector<MatchKeyParam> &match_key,
               const std::string &action_name,
               ActionData action_data,
               entry_handle_t *handle,
               int priority = -1  /*only used for ternary*/) {
    // table_add <table name> <action name> <match fields> => <action parameters> [priority]
    std::stringstream spade_ss;
    spade_ss << "command:table_add\\ " << table_name << "\\ " << action_name << "\\ ";
    // Borrowed from MatchKeyParam operator>> to avoid unneeded TYPE and formatting output
    for (auto it = match_key.begin(); it != match_key.end(); ++it) {
      bm::utils::dump_hexstring(spade_ss, it->key);
      switch (it->type) {
        case MatchKeyParam::Type::LPM:
          spade_ss << "/" << it->prefix_length;
          break;
        case MatchKeyParam::Type::TERNARY:
          spade_ss << "\\ &&&\\ ";
          bm::utils::dump_hexstring(spade_ss, it->mask);
          break;
        case MatchKeyParam::Type::RANGE:
          spade_ss << "\\ ->\\ ";
          bm::utils::dump_hexstring(spade_ss, it->mask);
          break;
        default:
          break;
      }
      spade_ss << "\\ ";
    }
    spade_ss << "=>";
    for (size_t q = 0; q < action_data.size(); ++q) {
      spade_ss << "\\ ";
      bm::utils::dump_hexstring(spade_ss, action_data.get(q).get_string());
    }
    if (priority > -1) spade_ss << "\\ " << priority;
    std::string spade_str = spade_ss.str();
    auto retval = Switch::mt_add_entry(
        cxt_id, table_name, match_key, action_name,
        std::move(action_data), handle, priority);
    ra_update_tblhash(cxt_id, table_name, spade_str);
    return retval;
  }

  MatchErrorCode
  mt_delete_entry(cxt_id_t cxt_id,
                  const std::string &table_name,
                  entry_handle_t handle) {
    auto retval = Switch::mt_delete_entry(cxt_id, table_name, handle);
    // table_delete <table_name> <handle>
    std::string spade_str = "command:table_delete\\ " + table_name + "\\ " + std::to_string(handle);
    ra_update_tblhash(cxt_id, table_name, spade_str);
    return retval;
  }

  MatchErrorCode
  mt_modify_entry(cxt_id_t cxt_id,
                  const std::string &table_name,
                  entry_handle_t handle,
                  const std::string &action_name,
                  ActionData action_data) override {
    // table_modify <table name> <action name> <entry handle> [action parameters]
    std::stringstream spade_ss;
    spade_ss << "command:table_modify\\ " << table_name << "\\ " << action_name << "\\ " << std::to_string(handle);
    for (size_t q = 0; q < action_data.size(); ++q) {
      spade_ss << "\\ ";
      bm::utils::dump_hexstring(spade_ss, action_data.get(q).get_string());
    }
    std::string spade_str = spade_ss.str();
    auto retval = Switch::mt_modify_entry(cxt_id,
        table_name, handle, action_name, std::move(action_data));
    ra_update_tblhash(cxt_id, table_name, spade_str);
    return retval;
  }

  // This grabs the JSON string and NOT the file name passed to the CLI
  RuntimeInterface::ErrorCode
  load_new_config(const std::string &new_config) {
    auto retval = Switch::load_new_config(new_config);
    loaded_config = new_config;
    return retval;
  }

  RuntimeInterface::ErrorCode
  swap_configs() {
    auto retval = Switch::swap_configs();
    ra_update_proghash();
    return retval;
  }

  SimpleSwitch(const SimpleSwitch &) = delete;
  SimpleSwitch &operator =(const SimpleSwitch &) = delete;
  SimpleSwitch(SimpleSwitch &&) = delete;
  SimpleSwitch &&operator =(SimpleSwitch &&) = delete;

 private:
  static constexpr size_t nb_egress_threads = 4u;
  static packet_id_t packet_id;

  class MirroringSessions;

  class InputBuffer;
  class SpadeBuffer;

  enum PktInstanceType {
    PKT_INSTANCE_TYPE_NORMAL,
    PKT_INSTANCE_TYPE_INGRESS_CLONE,
    PKT_INSTANCE_TYPE_EGRESS_CLONE,
    PKT_INSTANCE_TYPE_COALESCED,
    PKT_INSTANCE_TYPE_RECIRC,
    PKT_INSTANCE_TYPE_REPLICATION,
    PKT_INSTANCE_TYPE_RESUBMIT,
  };

  struct EgressThreadMapper {
    explicit EgressThreadMapper(size_t nb_threads)
        : nb_threads(nb_threads) { }

    size_t operator()(size_t egress_port) const {
      return egress_port % nb_threads;
    }

    size_t nb_threads;
  };

 private:
  void spade_thread();
  void ingress_thread();
  void egress_thread(size_t worker_id);
  void transmit_thread();

  ts_res get_ts() const;

  // TODO(antonin): switch to pass by value?
  void enqueue(port_t egress_port, std::unique_ptr<Packet> &&packet);

  void copy_field_list_and_set_type(
      const std::unique_ptr<Packet> &packet,
      const std::unique_ptr<Packet> &packet_copy,
      PktInstanceType copy_type, p4object_id_t field_list_id);

  void check_queueing_metadata();

  void multicast(Packet *packet, unsigned int mgid);

 private:
  port_t drop_port;
  bool enable_spade;
  std::string spade_file;
  uint32_t spade_switch_id;
  // std::unique_ptr<SpadeBuffer> spade_buffer;
  Queue<std::string> spade_buffer;
  std::vector<std::thread> threads_;
  std::unique_ptr<InputBuffer> input_buffer;
  // for these queues, the write operation is non-blocking and we drop the
  // packet if the queue is full
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
  bm::QueueingLogicPriRL<std::unique_ptr<Packet>, EgressThreadMapper>
#else
  bm::QueueingLogicRL<std::unique_ptr<Packet>, EgressThreadMapper>
#endif
  egress_buffers;
  Queue<std::unique_ptr<Packet> > output_buffer;
  TransmitFn my_transmit_fn;
  std::shared_ptr<McSimplePreLAG> pre;
  clock::time_point start;
  bool with_queueing_metadata{false};
  std::unique_ptr<MirroringSessions> mirroring_sessions;
};

#endif  // SIMPLE_SWITCH_SIMPLE_SWITCH_H_
