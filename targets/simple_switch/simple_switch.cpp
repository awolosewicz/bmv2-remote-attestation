/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
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
 * Antonin Bas
 *
 */

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>

#include <unistd.h>

#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

#include "simple_switch.h"
#include "register_access.h"

namespace {

struct hash_ex {
  uint32_t operator()(const char *buf, size_t s) const {
    const uint32_t p = 16777619;
    uint32_t hash = 2166136261;

    for (size_t i = 0; i < s; i++)
      hash = (hash ^ buf[i]) * p;

    hash += hash << 13;
    hash ^= hash >> 7;
    hash += hash << 3;
    hash ^= hash >> 17;
    hash += hash << 5;
    return static_cast<uint32_t>(hash);
  }
};

struct bmv2_hash {
  uint64_t operator()(const char *buf, size_t s) const {
    return bm::hash::xxh64(buf, s);
  }
};

}  // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex);
REGISTER_HASH(bmv2_hash);

extern int import_primitives(SimpleSwitch *simple_switch);

packet_id_t SimpleSwitch::packet_id = 0;

class SimpleSwitch::MirroringSessions {
 public:
  bool add_session(mirror_id_t mirror_id,
                   const MirroringSessionConfig &config) {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID) {
      sessions_map[mirror_id] = config;
      return true;
    } else {
      bm::Logger::get()->error("mirror_id out of range. No session added.");
      return false;
    }
  }

  bool delete_session(mirror_id_t mirror_id) {
    Lock lock(mutex);
    if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID) {
      return sessions_map.erase(mirror_id) == 1;
    } else {
      bm::Logger::get()->error("mirror_id out of range. No session deleted.");
      return false;
    }
  }

  bool get_session(mirror_id_t mirror_id,
                   MirroringSessionConfig *config) const {
    Lock lock(mutex);
    auto it = sessions_map.find(mirror_id);
    if (it == sessions_map.end()) return false;
    *config = it->second;
    return true;
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  mutable std::mutex mutex;
  std::unordered_map<mirror_id_t, MirroringSessionConfig> sessions_map;
};

// Arbitrates which packets are processed by the ingress thread. Resubmit and
// recirculate packets go to a high priority queue, while normal packets go to a
// low priority queue. We assume that starvation is not going to be a problem.
// Resubmit packets are dropped if the queue is full in order to make sure the
// ingress thread cannot deadlock. We do the same for recirculate packets even
// though the same argument does not apply for them. Enqueueing normal packets
// is blocking (back pressure is applied to the interface).
class SimpleSwitch::InputBuffer {
 public:
  enum class PacketType {
    NORMAL,
    RESUBMIT,
    RECIRCULATE,
    SENTINEL  // signal for the ingress thread to terminate
  };

  InputBuffer(size_t capacity_hi, size_t capacity_lo)
      : capacity_hi(capacity_hi), capacity_lo(capacity_lo) { }

  int push_front(PacketType packet_type, std::unique_ptr<Packet> &&item) {
    switch (packet_type) {
      case PacketType::NORMAL:
        return push_front(&queue_lo, capacity_lo, &cvar_can_push_lo,
                          std::move(item), true);
      case PacketType::RESUBMIT:
      case PacketType::RECIRCULATE:
        return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                          std::move(item), false);
      case PacketType::SENTINEL:
        return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                          std::move(item), true);
    }
    _BM_UNREACHABLE("Unreachable statement");
    return 0;
  }

  void pop_back(std::unique_ptr<Packet> *pItem) {
    Lock lock(mutex);
    cvar_can_pop.wait(
        lock, [this] { return (queue_hi.size() + queue_lo.size()) > 0; });
    // give higher priority to resubmit/recirculate queue
    if (queue_hi.size() > 0) {
      *pItem = std::move(queue_hi.back());
      queue_hi.pop_back();
      lock.unlock();
      cvar_can_push_hi.notify_one();
    } else {
      *pItem = std::move(queue_lo.back());
      queue_lo.pop_back();
      lock.unlock();
      cvar_can_push_lo.notify_one();
    }
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::unique_lock<Mutex>;
  using QueueImpl = std::deque<std::unique_ptr<Packet> >;

  int push_front(QueueImpl *queue, size_t capacity,
                 std::condition_variable *cvar,
                 std::unique_ptr<Packet> &&item, bool blocking) {
    Lock lock(mutex);
    while (queue->size() == capacity) {
      if (!blocking) return 0;
      cvar->wait(lock);
    }
    queue->push_front(std::move(item));
    lock.unlock();
    cvar_can_pop.notify_one();
    return 1;
  }

  mutable std::mutex mutex;
  mutable std::condition_variable cvar_can_push_hi;
  mutable std::condition_variable cvar_can_push_lo;
  mutable std::condition_variable cvar_can_pop;
  size_t capacity_hi;
  size_t capacity_lo;
  QueueImpl queue_hi;
  QueueImpl queue_lo;
};

// class SimpleSwitch::SpadeBuffer {
//  public:
//   using Mutex = std::mutex;
//   using Lock = std::unique_lock<Mutex>;

//   int push_front(std::string input) {
//     Lock lock(mutex);
//     queue.push_front(input);
//     lock.unlock()
//     cvar_can_pop.notify_one();
//     return 0;
//   }

//   void pop_back(std::string *output) {
//     Lock lock(mutex);
//     cvar_can_pop.wait(
//         lock, [this] { return queue.size() > 0; });
//     *output = std::move(queue.back());
//     queue.pop_back();
//     lock.unlock();
//   }

//  private:
//   mutable Mutex mutex;
//   mutable std::condition_variable cvar_can_pop;
//   std::deque<std::string> queue;
// }

SimpleSwitch::SimpleSwitch(bool enable_swap, port_t drop_port, bool enable_spade, std::string spade_file,
                           uint32_t spade_switch_id, uint32_t spade_verbosity, uint32_t spade_period)
  : Switch(enable_swap),
    drop_port(drop_port),
    enable_spade(enable_spade),
    spade_file(spade_file),
    spade_switch_id(spade_switch_id),
    spade_verbosity(spade_verbosity),
    spade_period(spade_period),
    input_buffer(new InputBuffer(
        1024 /* normal capacity */, 1024 /* resubmit/recirc capacity */)),
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    egress_buffers(nb_egress_threads,
                   64, EgressThreadMapper(nb_egress_threads),
                   SSWITCH_PRIORITY_QUEUEING_NB_QUEUES),
#else
    egress_buffers(nb_egress_threads,
                   64, EgressThreadMapper(nb_egress_threads)),
#endif
    output_buffer(128),
    spade_buffer(1024),
    // cannot use std::bind because of a clang bug
    // https://stackoverflow.com/questions/32030141/is-this-incorrect-use-of-stdbind-or-a-compiler-bug
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                          const char *buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
    }),
    pre(new McSimplePreLAG()),
    start(clock::now()),
    mirroring_sessions(new MirroringSessions()) {
  add_component<McSimplePreLAG>(pre);

  add_required_field("standard_metadata", "ingress_port");
  add_required_field("standard_metadata", "packet_length");
  add_required_field("standard_metadata", "instance_type");
  add_required_field("standard_metadata", "egress_spec");
  add_required_field("standard_metadata", "egress_port");

  force_arith_header("standard_metadata");
  force_arith_header("queueing_metadata");
  force_arith_header("intrinsic_metadata");

  import_primitives(this);
}

void
SimpleSwitch::spade_thread() {
  BMLOG_DEBUG("SPADE thread started");
  std::ofstream spade_pipe (get_spade_file(), std::ios::out);
  if (!spade_pipe.is_open()) {
    BMLOG_DEBUG("Failed to open SPADE pipe: {}", strerror(errno));
  }
  else {
    while (1) {
      std::string output;
      spade_buffer.pop_back(&output);
      BMLOG_DEBUG("SPADE: writing "+output)
      if (output == "") break;
      spade_pipe << output;
      std::flush(spade_pipe);
    }
    BMLOG_DEBUG("SPADE thread stopping")
    spade_pipe.close();
  }
}

//! Sends a vertex to SPADE with given type and vals as key:val pairs
//! See main.cpp for verbosity options
int
SimpleSwitch::spade_send_vertex(int type, uint64_t instance, spade_uid_t spade_uid, std::string vals) {
  if (!get_enable_spade()) {
    return -1;
  }
  std::stringstream spade_ss;
  //BMLOG_DEBUG("Writing vertex to spade with vals "+vals);
  switch(type) {
    case SPADE_VTYPE_AGENT:
      spade_ss << "type:Agent id:" << spade_uid << " time:" << instance 
                 << " switch:" << (int)(spade_switch_id / SPADE_SWITCH_ID_MULT) << " " << vals << std::endl;
      break;
    case SPADE_VTYPE_PROCESS:
      spade_ss << "type:Process id:" << spade_uid << " time:" << instance 
                 << " switch:" << (int)(spade_switch_id / SPADE_SWITCH_ID_MULT) << " " << vals << std::endl;
      break;
    case SPADE_VTYPE_ARTIFACT:
      spade_ss << "type:Artifact id:" << spade_uid << " time:" << instance 
                 << " switch:" << (int)(spade_switch_id / SPADE_SWITCH_ID_MULT) << " " << vals << std::endl;
      break;
  }
  const std::string to_write = spade_ss.str();
  spade_buffer.push_front(std::move(to_write));
  return 0;
}

//! Sends an edge to SPADE with given type and uids for from and to, also with key:val pairs
//! See main.cpp for verbosity options
int
SimpleSwitch::spade_send_edge(int type, uint64_t instance, spade_uid_t from, spade_uid_t to, std::string vals) {
  if (!get_enable_spade()) {
    return -1;
  }
  //BMLOG_DEBUG("Writing edge to spade with vals "+vals);
  std::stringstream spade_ss;
  switch(type) {
    case SPADE_ETYPE_USED:
      spade_ss << "type:Used time:" << instance
                 << " from:" << from << " to:" << to << " " << vals << std::endl;
      break;
    case SPADE_ETYPE_GENERATEDBY:
      spade_ss << "type:WasGeneratedBy time:" << instance
                 << " from:" << from << " to:" << to << " " << vals << std::endl;
      break;
    case SPADE_ETYPE_TRIGGEREDBY:
      spade_ss << "type:WasTriggeredBy time:" << instance
                 << " from:" << from << " to:" << to << " " << vals << std::endl;
      break;
    case SPADE_ETYPE_DERIVEDFROM:
      spade_ss << "type:WasDerivedFrom time:" << instance
                 << " from:" << from << " to:" << to << " " << vals << std::endl;
      break;
    case SPADE_ETYPE_CONTROLLEDBY:
      spade_ss << "type:WasControlledBy time:" << instance
                 << " from:" << from << " to:" << to << " " << vals << std::endl;
      break;
  }
  const std::string to_write = spade_ss.str();
  spade_buffer.push_front(std::move(to_write));
  return 0;
}

int
SimpleSwitch::spade_setup_ports() {
  std::map<bm::DevMgrIface::port_t, bm::DevMgrIface::PortInfo> portinfo = get_port_info();
  uint64_t instance = get_time_since_epoch_us()/1000;
  uint32_t spade_switch_id_special = spade_switch_id / 10;
  for (auto it = portinfo.begin(); it != portinfo.end(); ++it) {
    int rc = spade_send_vertex(SPADE_VTYPE_PROCESS, instance, spade_switch_id_special + spade_uid_ctr, "subtype:swport_in num:"+std::to_string(it->first));
    if (rc != 0) return -1;
    spade_port_in_ids.insert({it->first, spade_switch_id_special + spade_uid_ctr++});
  }
  for (auto it = portinfo.begin(); it != portinfo.end(); ++it) {
    int rc = spade_send_vertex(SPADE_VTYPE_PROCESS, instance, spade_switch_id_special + spade_uid_ctr, "subtype:swport_out num:"+std::to_string(it->first));
    if (rc != 0) return -1;
    spade_port_out_ids.insert({it->first, spade_switch_id_special + spade_uid_ctr++});
  }
  int rc = spade_send_vertex(SPADE_VTYPE_PROCESS, instance, spade_switch_id_special + spade_uid_ctr, "subtype:drop num:"+std::to_string(get_drop_port()));
  if (rc != 0) return -1;
  spade_port_out_ids.insert({get_drop_port(), spade_switch_id_special + spade_uid_ctr++});
  return 0;
}

int
SimpleSwitch::receive_(port_t port_num, const char *buffer, int len) {
  // we limit the packet buffer to original size + 512 bytes, which means we
  // cannot add more than 512 bytes of header data to the packet, which should
  // be more than enough
  auto packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(len + 512, buffer, len));

  BMELOG(packet_in, *packet);

  PHV *phv = packet->get_phv();
  // many current P4 programs assume this
  // it is also part of the original P4 spec
  phv->reset_metadata();
  RegisterAccess::clear_all(packet.get());

  // setting standard metadata

  phv->get_field("standard_metadata.ingress_port").set(port_num);
  // using packet register 0 to store length, this register will be updated for
  // each add_header / remove_header primitive call
  packet->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, len);
  phv->get_field("standard_metadata.packet_length").set(len);
  Field &f_instance_type = phv->get_field("standard_metadata.instance_type");
  f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

  if (phv->has_field("intrinsic_metadata.ingress_global_timestamp")) {
    phv->get_field("intrinsic_metadata.ingress_global_timestamp")
        .set(get_ts().count());
  }

  input_buffer->push_front(
      InputBuffer::PacketType::NORMAL, std::move(packet));
  return 0;
}

void
SimpleSwitch::start_and_return_() {
  check_queueing_metadata();

  threads_.push_back(std::thread(&SimpleSwitch::ingress_thread, this));
  for (size_t i = 0; i < nb_egress_threads; i++) {
    threads_.push_back(std::thread(&SimpleSwitch::egress_thread, this, i));
  }
  threads_.push_back(std::thread(&SimpleSwitch::transmit_thread, this));
  threads_.push_back(std::thread(&SimpleSwitch::spade_thread, this));
  ra_update_proghash();
}

void
SimpleSwitch::swap_notify_() {
  bm::Logger::get()->debug(
      "simple_switch target has been notified of a config swap");
  check_queueing_metadata();
}

SimpleSwitch::~SimpleSwitch() {
  input_buffer->push_front(
      InputBuffer::PacketType::SENTINEL, nullptr);
  for (size_t i = 0; i < nb_egress_threads; i++) {
    // The push_front call is called inside a while loop because there is no
    // guarantee that the sentinel was enqueued otherwise. It should not be an
    // issue because at this stage the ingress thread has been sent a signal to
    // stop, and only egress clones can be sent to the buffer.
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    while (egress_buffers.push_front(i, 0, nullptr) == 0) continue;
#else
    while (egress_buffers.push_front(i, nullptr) == 0) continue;
#endif
  }
  output_buffer.push_front(nullptr);
  spade_buffer.push_front("");
  for (auto& thread_ : threads_) {
    thread_.join();
  }
}

void
SimpleSwitch::reset_target_state_() {
  bm::Logger::get()->debug("Resetting simple_switch target-specific state");
  get_component<McSimplePreLAG>()->reset_state();
}

bool
SimpleSwitch::mirroring_add_session(mirror_id_t mirror_id,
                                    const MirroringSessionConfig &config) {
  return mirroring_sessions->add_session(mirror_id, config);
}

bool
SimpleSwitch::mirroring_delete_session(mirror_id_t mirror_id) {
  return mirroring_sessions->delete_session(mirror_id);
}

bool
SimpleSwitch::mirroring_get_session(mirror_id_t mirror_id,
                                    MirroringSessionConfig *config) const {
  return mirroring_sessions->get_session(mirror_id, config);
}

int
SimpleSwitch::set_egress_queue_depth(size_t port, const size_t depth_pkts) {
  egress_buffers.set_capacity(port, depth_pkts);
  return 0;
}

int
SimpleSwitch::set_all_egress_queue_depths(const size_t depth_pkts) {
  egress_buffers.set_capacity_for_all(depth_pkts);
  return 0;
}

int
SimpleSwitch::set_egress_queue_rate(size_t port, const uint64_t rate_pps) {
  egress_buffers.set_rate(port, rate_pps);
  return 0;
}

int
SimpleSwitch::set_all_egress_queue_rates(const uint64_t rate_pps) {
  egress_buffers.set_rate_for_all(rate_pps);
  return 0;
}

uint64_t
SimpleSwitch::get_time_elapsed_us() const {
  return get_ts().count();
}

uint64_t
SimpleSwitch::get_time_since_epoch_us() const {
  auto tp = clock::now();
  return duration_cast<ts_res>(tp.time_since_epoch()).count();
}

void
SimpleSwitch::set_transmit_fn(TransmitFn fn) {
  my_transmit_fn = std::move(fn);
}


// RA Register Access
void 
SimpleSwitch::set_ra_registers(unsigned char *val, unsigned int idx) {
  idx *= 16; //0-15 for registers, 16-31 for tables, 32-48 for program
  memcpy(&ra_registers[idx], val, 16);
}
unsigned char* 
SimpleSwitch::get_ra_register(unsigned int idx) {
  idx *= 16;
  return &ra_registers[idx];
}


void
SimpleSwitch::transmit_thread() {
  while (1) {
    std::unique_ptr<Packet> packet;
    output_buffer.pop_back(&packet);
    if (packet == nullptr) break;
    BMELOG(packet_out, *packet);
    BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
                    packet->get_data_size(), packet->get_egress_port());
    my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
                   packet->data(), packet->get_data_size());
  }
}

ts_res
SimpleSwitch::get_ts() const {
  return duration_cast<ts_res>(clock::now() - start);
}

void
SimpleSwitch::enqueue(port_t egress_port, std::unique_ptr<Packet> &&packet) {
    packet->set_egress_port(egress_port);

    PHV *phv = packet->get_phv();

    if (with_queueing_metadata) {
      phv->get_field("queueing_metadata.enq_timestamp").set(get_ts().count());
      phv->get_field("queueing_metadata.enq_qdepth")
          .set(egress_buffers.size(egress_port));
    }

#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    size_t priority = phv->has_field(SSWITCH_PRIORITY_QUEUEING_SRC) ?
        phv->get_field(SSWITCH_PRIORITY_QUEUEING_SRC).get<size_t>() : 0u;
    if (priority >= SSWITCH_PRIORITY_QUEUEING_NB_QUEUES) {
      bm::Logger::get()->error("Priority out of range, dropping packet");
      return;
    }
    egress_buffers.push_front(
        egress_port, SSWITCH_PRIORITY_QUEUEING_NB_QUEUES - 1 - priority,
        std::move(packet));
#else
    egress_buffers.push_front(egress_port, std::move(packet));
#endif
}

// used for ingress cloning, resubmit
void
SimpleSwitch::copy_field_list_and_set_type(
    const std::unique_ptr<Packet> &packet,
    const std::unique_ptr<Packet> &packet_copy,
    PktInstanceType copy_type, p4object_id_t field_list_id) {
  PHV *phv_copy = packet_copy->get_phv();
  phv_copy->reset_metadata();
  FieldList *field_list = this->get_field_list(field_list_id);
  field_list->copy_fields_between_phvs(phv_copy, packet->get_phv());
  phv_copy->get_field("standard_metadata.instance_type").set(copy_type);
}

void
SimpleSwitch::check_queueing_metadata() {
  // TODO(antonin): add qid in required fields
  bool enq_timestamp_e = field_exists("queueing_metadata", "enq_timestamp");
  bool enq_qdepth_e = field_exists("queueing_metadata", "enq_qdepth");
  bool deq_timedelta_e = field_exists("queueing_metadata", "deq_timedelta");
  bool deq_qdepth_e = field_exists("queueing_metadata", "deq_qdepth");
  if (enq_timestamp_e || enq_qdepth_e || deq_timedelta_e || deq_qdepth_e) {
    if (enq_timestamp_e && enq_qdepth_e && deq_timedelta_e && deq_qdepth_e) {
      with_queueing_metadata = true;
      return;
    } else {
      bm::Logger::get()->warn(
          "Your JSON input defines some but not all queueing metadata fields");
    }
  }
  with_queueing_metadata = false;
}

void
SimpleSwitch::multicast(Packet *packet, unsigned int mgid) {
  auto *phv = packet->get_phv();
  auto &f_rid = phv->get_field("intrinsic_metadata.egress_rid");
  const auto pre_out = pre->replicate({mgid});
  auto packet_size =
      packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
  for (const auto &out : pre_out) {
    auto egress_port = out.egress_port;
    BMLOG_DEBUG_PKT(*packet, "Replicating packet on port {}", egress_port);
    f_rid.set(out.rid);
    std::unique_ptr<Packet> packet_copy = packet->clone_with_phv_ptr();
    RegisterAccess::clear_all(packet_copy.get());
    packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                              packet_size);
    enqueue(egress_port, std::move(packet_copy));
  }
}

unsigned short
SimpleSwitch::get_packet_etype(bm::Packet* packet) {
  char * packet_data = packet->data() + 12; // Get to etype
  unsigned short etype = (short)(*packet_data << 8) | (short)(255 & *(packet_data + 1));
  if (etype == 0x88A8) { // 802.1Q double
    packet_data += 8;
    etype = (short)(*packet_data << 8) | (short)(255 & *(packet_data + 1));
  }
  else if (etype == 0x8100) { // 802.1Q single
    packet_data += 4;
    etype = (short)(*packet_data << 8) | (short)(255 & *(packet_data + 1));
  }
  return etype;
}

char *
SimpleSwitch::get_post_ethernet(bm::Packet* packet) {
  char * packet_data = packet->data() + 12;
  unsigned short etype = (short)(*packet_data << 8) | (short)(255 & *(packet_data + 1));
  if (etype == 0x88A8) { // 802.1Q double
    packet_data += 8;
  }
  else if (etype == 0x8100) { // 802.1Q single
    packet_data += 4;
  }
  packet_data += 2;
  return packet_data;
}

void
SimpleSwitch::ingress_thread() {
  PHV *phv;

  while (1) {
    std::unique_ptr<Packet> packet;
    input_buffer->pop_back(&packet);
    if (packet == nullptr) break;

    // TODO(antonin): only update these if swapping actually happened?
    Parser *parser = this->get_parser("parser");
    Pipeline *ingress_mau = this->get_pipeline("ingress");

    phv = packet->get_phv();

    port_t ingress_port = packet->get_ingress_port();
    (void) ingress_port;
    BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}",
                    ingress_port);
    auto ingress_packet_size =
        packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);

    /* This looks like it comes out of the blue. However this is needed for
       ingress cloning. The parser updates the buffer state (pops the parsed
       headers) to make the deparser's job easier (the same buffer is
       re-used). But for ingress cloning, the original packet is needed. This
       kind of looks hacky though. Maybe a better solution would be to have the
       parser leave the buffer unchanged, and move the pop logic to the
       deparser. TODO? */
    const Packet::buffer_state_t packet_in_state = packet->save_buffer_state();

    std::stringstream spade_ss;
    spade_uid_t input_uid = spade_switch_id + (packet->get_packet_id() * 10) + packet->get_copy_id();;
    uint64_t instance = get_time_since_epoch_us()/1000;
    bool do_write_vertex = false;
    switch (spade_verbosity) {
      case 0:
        {
          spade_ss << "subtype:packet_in size:" << (int)packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX) 
                  << " ethertype:0x" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex 
                  << (int)get_packet_etype(packet.get());
          do_write_vertex = true;
          break;
        }
      case 3:
        {
          std::string src = "";
          std::string dst = "";
          std::string prot;
          if ((int)get_packet_etype(packet.get()) == 0x0800) {
            uint8_t * packet_data = (uint8_t *)(get_post_ethernet(packet.get()) + 9); // get to protocol
            prot = std::to_string(*packet_data);
            packet_data += 3;
            for (int i = 0; i < 4; ++i) {
              src += std::to_string(*packet_data++);
              if (i < 3) {
                src += ".";
              }
            }
            for (int i = 0; i < 4; ++i) {
              dst += std::to_string(*packet_data++);
              if (i < 3) {
                dst += ".";
              }
            }
          }
          spade_ss << "subtype:flow src:" << src << " dst:" << dst << " protocol:" << prot;
          std::string spade_string = spade_ss.str();
          auto it = spade_recorded_flows.find(spade_string);
          if (it == spade_recorded_flows.end()) {
            // insert_or_assign not supported with used compiler version
            spade_recorded_flows.insert({spade_string, instance / spade_period});
            do_write_vertex = true;
          }
          else if ((instance / spade_period) != it->second) {
            spade_recorded_flows[spade_string] = instance / spade_period;
            do_write_vertex = true;
          }
          break;
        }
    }
    if (do_write_vertex) {
      int spade_rc = spade_send_vertex(SPADE_VTYPE_ARTIFACT, instance, input_uid, spade_ss.str());
      if (spade_rc != 0) {
        BMLOG_DEBUG_PKT(*packet, "Failed to write packet ingress vertex")
      }
      else {
        RegisterAccess::set_spade_input_uid(packet.get(), input_uid);
        spade_rc = spade_send_edge(SPADE_ETYPE_GENERATEDBY, instance, input_uid,
                                   spade_port_in_ids.find(packet->get_ingress_port())->second, "");
        if (spade_rc != 0) BMLOG_DEBUG_PKT(*packet, "Failed to write packet ingress edge");
      }
    }
    else {
      RegisterAccess::set_spade_input_uid(packet.get(), 0); // see packet.h, registers are default-initialized arrays
    }

    parser->parse(packet.get());

    if (phv->has_field("standard_metadata.parser_error")) {
      phv->get_field("standard_metadata.parser_error").set(
          packet->get_error_code().get());
    }

    if (phv->has_field("standard_metadata.checksum_error")) {
      phv->get_field("standard_metadata.checksum_error").set(
           packet->get_checksum_error() ? 1 : 0);
    }

    ingress_mau->apply(packet.get());

    packet->reset_exit();

    Field &f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    port_t egress_spec = f_egress_spec.get_uint();

    auto clone_mirror_session_id =
        RegisterAccess::get_clone_mirror_session_id(packet.get());
    auto clone_field_list = RegisterAccess::get_clone_field_list(packet.get());

    int learn_id = RegisterAccess::get_lf_field_list(packet.get());
    unsigned int mgid = 0u;

    // detect mcast support, if this is true we assume that other fields needed
    // for mcast are also defined
    if (phv->has_field("intrinsic_metadata.mcast_grp")) {
      Field &f_mgid = phv->get_field("intrinsic_metadata.mcast_grp");
      mgid = f_mgid.get_uint();
    }

    // INGRESS CLONING
    if (clone_mirror_session_id) {
      BMLOG_DEBUG_PKT(*packet, "Cloning packet at ingress");
      RegisterAccess::set_clone_mirror_session_id(packet.get(), 0);
      RegisterAccess::set_clone_field_list(packet.get(), 0);
      MirroringSessionConfig config;
      // Extract the part of clone_mirror_session_id that contains the
      // actual session id.
      clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
      bool is_session_configured = mirroring_get_session(
          static_cast<mirror_id_t>(clone_mirror_session_id), &config);
      if (is_session_configured) {
        const Packet::buffer_state_t packet_out_state =
            packet->save_buffer_state();
        packet->restore_buffer_state(packet_in_state);
        p4object_id_t field_list_id = clone_field_list;
        std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
        RegisterAccess::clear_all(packet_copy.get());
        packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                                  ingress_packet_size);
        RegisterAccess::set_spade_input_uid(packet_copy.get(), RegisterAccess::get_spade_input_uid(packet.get()));
        // we need to parse again
        // the alternative would be to pay the (huge) price of PHV copy for
        // every ingress packet
        parser->parse(packet_copy.get());
        copy_field_list_and_set_type(packet, packet_copy,
                                     PKT_INSTANCE_TYPE_INGRESS_CLONE,
                                     field_list_id);
        if (config.mgid_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
          multicast(packet_copy.get(), config.mgid);
        }
        if (config.egress_port_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                          config.egress_port);
          enqueue(config.egress_port, std::move(packet_copy));
        }
        packet->restore_buffer_state(packet_out_state);
      }
    }

    // LEARNING
    if (learn_id > 0) {
      get_learn_engine()->learn(learn_id, *packet.get());
    }

    // RESUBMIT
    auto resubmit_flag = RegisterAccess::get_resubmit_flag(packet.get());
    if (resubmit_flag) {
      BMLOG_DEBUG_PKT(*packet, "Resubmitting packet");
      // get the packet ready for being parsed again at the beginning of
      // ingress
      packet->restore_buffer_state(packet_in_state);
      p4object_id_t field_list_id = resubmit_flag;
      RegisterAccess::set_resubmit_flag(packet.get(), 0);
      // TODO(antonin): a copy is not needed here, but I don't yet have an
      // optimized way of doing this
      std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
      PHV *phv_copy = packet_copy->get_phv();
      copy_field_list_and_set_type(packet, packet_copy,
                                   PKT_INSTANCE_TYPE_RESUBMIT,
                                   field_list_id);
      RegisterAccess::clear_all(packet_copy.get());
      packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                                ingress_packet_size);
      phv_copy->get_field("standard_metadata.packet_length")
          .set(ingress_packet_size);
      input_buffer->push_front(
          InputBuffer::PacketType::RESUBMIT, std::move(packet_copy));
      continue;
    }

    // MULTICAST
    if (mgid != 0) {
      BMLOG_DEBUG_PKT(*packet, "Multicast requested for packet");
      auto &f_instance_type = phv->get_field("standard_metadata.instance_type");
      f_instance_type.set(PKT_INSTANCE_TYPE_REPLICATION);
      multicast(packet.get(), mgid);
      // when doing multicast, we discard the original packet
      continue;
    }

    port_t egress_port = egress_spec;
    BMLOG_DEBUG_PKT(*packet, "Egress port is {}", egress_port);

    if (egress_port == drop_port) {  // drop packet
      uint64_t instance = get_time_since_epoch_us()/1000;
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
      spade_uid_t input_uid = RegisterAccess::get_spade_input_uid(packet.get());
      spade_send_edge(SPADE_ETYPE_USED, instance, spade_port_out_ids.find(drop_port)->second, input_uid, "");
      spade_send_edge(SPADE_ETYPE_DERIVEDFROM, instance, input_uid, spade_prev_prog, "");
      continue;
    }
    auto &f_instance_type = phv->get_field("standard_metadata.instance_type");
    f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

    enqueue(egress_port, std::move(packet));
  }
}

void
SimpleSwitch::egress_thread(size_t worker_id) {
  PHV *phv;

  while (1) {
    std::unique_ptr<Packet> packet;
    size_t port;
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
    size_t priority;
    egress_buffers.pop_back(worker_id, &port, &priority, &packet);
#else
    egress_buffers.pop_back(worker_id, &port, &packet);
#endif
    if (packet == nullptr) break;

    Deparser *deparser = this->get_deparser("deparser");
    Pipeline *egress_mau = this->get_pipeline("egress");

    phv = packet->get_phv();

    if (phv->has_field("intrinsic_metadata.egress_global_timestamp")) {
      phv->get_field("intrinsic_metadata.egress_global_timestamp")
          .set(get_ts().count());
    }

    if (with_queueing_metadata) {
      auto enq_timestamp =
          phv->get_field("queueing_metadata.enq_timestamp").get<ts_res::rep>();
      phv->get_field("queueing_metadata.deq_timedelta").set(
          get_ts().count() - enq_timestamp);
      phv->get_field("queueing_metadata.deq_qdepth").set(
          egress_buffers.size(port));
      if (phv->has_field("queueing_metadata.qid")) {
        auto &qid_f = phv->get_field("queueing_metadata.qid");
#ifdef SSWITCH_PRIORITY_QUEUEING_ON
        qid_f.set(SSWITCH_PRIORITY_QUEUEING_NB_QUEUES - 1 - priority);
#else
        qid_f.set(0);
#endif
      }
    }

    phv->get_field("standard_metadata.egress_port").set(port);

    Field &f_egress_spec = phv->get_field("standard_metadata.egress_spec");
    f_egress_spec.set(0);

    phv->get_field("standard_metadata.packet_length").set(
        packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX));

    egress_mau->apply(packet.get());

    auto clone_mirror_session_id =
        RegisterAccess::get_clone_mirror_session_id(packet.get());
    auto clone_field_list = RegisterAccess::get_clone_field_list(packet.get());

    // EGRESS CLONING
    if (clone_mirror_session_id) {
      BMLOG_DEBUG_PKT(*packet, "Cloning packet at egress");
      RegisterAccess::set_clone_mirror_session_id(packet.get(), 0);
      RegisterAccess::set_clone_field_list(packet.get(), 0);
      MirroringSessionConfig config;
      // Extract the part of clone_mirror_session_id that contains the
      // actual session id.
      clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
      bool is_session_configured = mirroring_get_session(
          static_cast<mirror_id_t>(clone_mirror_session_id), &config);
      if (is_session_configured) {
        p4object_id_t field_list_id = clone_field_list;
        std::unique_ptr<Packet> packet_copy =
            packet->clone_with_phv_reset_metadata_ptr();
        PHV *phv_copy = packet_copy->get_phv();
        FieldList *field_list = this->get_field_list(field_list_id);
        field_list->copy_fields_between_phvs(phv_copy, phv);
        phv_copy->get_field("standard_metadata.instance_type")
            .set(PKT_INSTANCE_TYPE_EGRESS_CLONE);
        auto packet_size =
            packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
        RegisterAccess::clear_all(packet_copy.get());
        packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                                  packet_size);
        if (config.mgid_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
          multicast(packet_copy.get(), config.mgid);
        }
        if (config.egress_port_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                          config.egress_port);
          enqueue(config.egress_port, std::move(packet_copy));
        }
      }
    }

    // TODO(antonin): should not be done like this in egress pipeline
    port_t egress_spec = f_egress_spec.get_uint();
    if (egress_spec == drop_port) {  // drop packet
      uint64_t instance = get_time_since_epoch_us()/1000;
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of egress");
      spade_uid_t input_uid = RegisterAccess::get_spade_input_uid(packet.get());
      spade_send_edge(SPADE_ETYPE_USED, instance, spade_port_out_ids.find(drop_port)->second, input_uid, "");
      spade_send_edge(SPADE_ETYPE_DERIVEDFROM, instance, input_uid, spade_prev_prog, "");
      
      continue;
    }

    deparser->deparse(packet.get());

    // Post-Deparse add RA data to an ethernet broadcast egressing on port 0
    std::unique_ptr<Packet> packet_ra = packet->clone_with_phv_ptr();
    packet_ra->set_egress_port(0);
    char *packetDataEgress = packet_ra->data();
    char *packetDataEgressStart = packetDataEgress;
    // Set destination MAC to ff:ff:ff:ff:ff:ff
    for (int i = 0; i < 6; i++) {
      *packetDataEgress = 255;
      packetDataEgress += 1;
    }
    packetDataEgress += 6; // src = 48 bits = 6 bytes
    unsigned short etype = (short)(*packetDataEgress << 8) | (short)(255 & *(packetDataEgress + 1));

    BMLOG_DEBUG_PKT(*packet_ra, "[RA Post-Deparse] Beginning post-deparse possibly adding new RA extension");
    size_t sizeIPData = 12;
    if (etype == 34984) { // 802.1Q double, 0x88A8
      BMLOG_DEBUG_PKT(*packet_ra, "[RA Post-Deparse] Found ethertype 802.1Q double");
      sizeIPData += 8;
      packetDataEgress += 8;
    }
    else if (etype == 33024) { // 802.1Q single, 0x8100
      BMLOG_DEBUG_PKT(*packet_ra, "[RA Post-Deparse] Found ethertype 802.1Q single");
      sizeIPData += 4;
      packetDataEgress += 4;
    }
    // Write attestation etype (testing, 34850, 0x8822)
    *(packetDataEgress++) = 136;
    *(packetDataEgress++) = 34;
    sizeIPData += 2;
    char *packetDataNew = packet_ra->prepend(96);
    memmove(packetDataNew, packetDataEgressStart, sizeIPData);
    packetDataEgress = packetDataNew + sizeIPData;
    for (int q = 0; q < (int)(nb_ra_registers); q++) {
      memcpy(packetDataEgress, get_ra_register(q), 16);
      packetDataEgress += 16;
      sizeIPData += 16;
    }
    BMLOG_DEBUG_PKT(*packet_ra, "[RA Post-Deparse] Truncating to {} bytes", sizeIPData);
    packet_ra->truncate(sizeIPData);

    // RECIRCULATE
    auto recirculate_flag = RegisterAccess::get_recirculate_flag(packet.get());
    if (recirculate_flag) {
      BMLOG_DEBUG_PKT(*packet, "Recirculating packet");
      p4object_id_t field_list_id = recirculate_flag;
      RegisterAccess::set_recirculate_flag(packet.get(), 0);
      FieldList *field_list = this->get_field_list(field_list_id);
      // TODO(antonin): just like for resubmit, there is no need for a copy
      // here, but it is more convenient for this first prototype
      std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
      PHV *phv_copy = packet_copy->get_phv();
      phv_copy->reset_metadata();
      field_list->copy_fields_between_phvs(phv_copy, phv);
      phv_copy->get_field("standard_metadata.instance_type")
          .set(PKT_INSTANCE_TYPE_RECIRC);
      size_t packet_size = packet_copy->get_data_size();
      RegisterAccess::clear_all(packet_copy.get());
      packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                                packet_size);
      phv_copy->get_field("standard_metadata.packet_length").set(packet_size);
      // TODO(antonin): really it may be better to create a new packet here or
      // to fold this functionality into the Packet class?
      packet_copy->set_ingress_length(packet_size);
      input_buffer->push_front(
          InputBuffer::PacketType::RECIRCULATE, std::move(packet_copy));
      continue;
    }

    std::stringstream spade_ss;
    spade_uid_t output_uid = spade_switch_id + (packet->get_packet_id() * 10) + packet->get_copy_id() + 1;
    uint64_t instance = get_time_since_epoch_us()/1000;
    switch (spade_verbosity) {
      case 0:
      {
        spade_ss << "subtype:packet_out size:" << (int)packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX) 
                << " ethertype:0x" << std::uppercase << std::setfill('0') << std::setw(4) << std::hex 
                << (int)get_packet_etype(packet.get());
        int rc = spade_send_vertex(SPADE_VTYPE_ARTIFACT, instance, output_uid, spade_ss.str());
        if (rc != 0) {
          BMLOG_DEBUG_PKT(*packet, "Failed to write packet egress vertex")
        }
        else {
          spade_send_edge(SPADE_ETYPE_DERIVEDFROM, instance, output_uid, spade_prev_prog, "");
          spade_send_edge(SPADE_ETYPE_DERIVEDFROM, instance, output_uid, RegisterAccess::get_spade_input_uid(packet.get()), "");
          spade_send_edge(SPADE_ETYPE_USED, instance, spade_port_out_ids.find(packet->get_egress_port())->second, output_uid, "");
        }
        break;
      }
      case 3:
      {
        if (packet->get_copy_id() != 0) break;
        spade_uid_t input_uid = RegisterAccess::get_spade_input_uid(packet.get());;
        if (input_uid == 0) break;
        spade_send_edge(SPADE_ETYPE_DERIVEDFROM, instance, input_uid, spade_prev_prog, "");
        spade_send_edge(SPADE_ETYPE_USED, instance, spade_port_out_ids.find(packet->get_egress_port())->second, input_uid, "");
        break;
      }
    }
    output_buffer.push_front(std::move(packet));
    output_buffer.push_front(std::move(packet_ra));
  }
}
