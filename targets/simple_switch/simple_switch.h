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

#include "md5.h"

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

using ts_res = std::chrono::microseconds;
using std::chrono::duration_cast;
using ticks = std::chrono::nanoseconds;

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

struct HashNode {
  std::string key;
  unsigned char hash[16];
};

class HashList {
  std::vector<HashNode> list;
  unsigned char list_hash[16] = {0};

  void* find(std::string target) {
    for (auto it = list.begin(), it != list.end(), ++it) {
      if (it->key == target) return it;
    }
    return nullptr;
  }

  void add(std::string nkey, unsigned char* nhash) {
    HashNode* node = (HashNode*)malloc(sizeof(HashNode));
    node->key = nkey;
    memcpy(node->hash, nhash, 16);
    list.push_back(node);
    for (int i = 0; i < 16, ++i) {
      list_hash[i] += nhash[i];
    }
  }

  void set(HashNode* node, unsigned char* nhash) {
    for (int i = 0; i < 16, ++i) {
      list_hash[i] -= node->hash[i];
      list_hash[i] += nhash[i];
    }
    memcpy(node->hash, nhash, 16);
  }
}

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

 private:
  using clock = std::chrono::high_resolution_clock;

  // Remote Attestation registers
  static constexpr size_t nb_ra_registers = 3;
  unsigned char ra_registers[16*nb_ra_registers];
  mutable boost::shared_mutex ra_mutex{};

 public:
  // by default, swapping is off
  explicit SimpleSwitch(bool enable_swap = true,
                        port_t drop_port = default_drop_port);

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

  // RA Register Access
  void set_ra_registers(unsigned char *val, unsigned int idx);
  unsigned char* get_ra_register(unsigned int idx);
  HashList registers;
  HashList tables;
  void ra_update_reghash(cxt_id_t cxt_id, const std::string &register_name) {
    boost::shard_lock<boost::shared_mutex> lock(ra_mutex);
    MD5_CTX reg_md5_ctx;
    MD5_INIT(&reg_md5_ctx);
    std::string tempstr = contexts.at(cxt_id).register_read_all(register_name)->get_string_repr();
    MD5_Update(&reg_md5_ctx, tempstr.data(), tempstr.size());
    unsigned char reg_md5[16];
    MD5_Final(reg_md5, &reg_md5_ctx);
    HashNode regnode = registers.find(register_name);
    if (regnode == nullptr) {
      registers.add(register_name, reg_md5);
    }
    else {
      registers.set(regnode, reg_md5);
    }
    set_ra_registers(registers.list_hash, 0);
  }
  void ra_update_tblhash(const std::string &table_name) {
    boost::shard_lock<boost::shared_mutex> lock(ra_mutex);
    MD5_CTX tbl_md5_ctx;
    MD5_INIT(&tbl_md5_ctx);
    std::vector<MatchTable::Entry> tbl_entries = Context::mt_get_entries<MatchTable>(table_name);
    MD5_Update(tbl_md5_ctx, tbl_entries.data(), tbl_entries.size());
    unsigned char tbl_md5[16];
    MD5_Final(tbl_md5, &tbl_md5_ctx);
    HashNode tblnode = tables.find(table_name);
    if (tblnode == nullptr) {
      tables.add(table_name, tbl_md5);
    }
    else {
      tables.set(tblnode, tbl_md5);
    }
    set_ra_registers(tables.list_hash, 1);
  } 
  void swap_notify_() override {
    set_ra_registers(get_config_md5().data(), 2);
    // memcpy(get_ra_register(2), get_config_md5().data(), 16);
  }

  // Hook register_write to update the RA register for registers
  // Read the entire register and MD5 hash it
  // If we've encountered this register before, find it in hashlist and update
  // Otherwise, add it to the list
  RegisterErrorCode
  register_write(cxt_id_t cxt_id,
                 const std::string &register_name,
                 const size_t idx, Data value) override {
    auto retval = contexts.at(cxt_id).register_write(
        register_name, idx, std::move(value));
    ra_update_reghash(cxt_id, register_name);
    return retval;
  }

  MatchErrorCode
  mt_clear_entries(cxt_id_t cxt_id,
                   const std::string &table_name,
                   bool reset_default_entry) override {
    auto retval = contexts.at(cxt_id).mt_clear_entries(table_name,
                                                reset_default_entry);
    ra_update_tblhash(table_name);
    return retval;
  }

  MatchErrorCode
  mt_add_entry(cxt_id_t cxt_id,
               const std::string &table_name,
               const std::vector<MatchKeyParam> &match_key,
               const std::string &action_name,
               ActionData action_data,
               entry_handle_t *handle,
               int priority = -1  /*only used for ternary*/) override {
    auto retval = contexts.at(cxt_id).mt_add_entry(
        table_name, match_key, action_name,
        std::move(action_data), handle, priority);
    ra_update_tblhash(table_name);
    return retval;
  }

  MatchErrorCode
  mt_delete_entry(cxt_id_t cxt_id,
                  const std::string &table_name,
                  entry_handle_t handle) override {
    auto retval = contexts.at(cxt_id).mt_delete_entry(table_name, handle);
    ra_update_tblhash(table_name);
    return retval;
  }

  MatchErrorCode
  mt_modify_entry(cxt_id_t cxt_id,
                  const std::string &table_name,
                  entry_handle_t handle,
                  const std::string &action_name,
                  ActionData action_data) override {
    auto retval = contexts.at(cxt_id).mt_modify_entry(
        table_name, handle, action_name, std::move(action_data));
    ra_update_tblhash(table_name);
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
