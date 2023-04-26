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

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/headers.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/phv_source.h>

#include <unistd.h>

#include <condition_variable>
#include <deque>
#include <iostream>
#include <fstream>
#include <mutex>
#include <string>

#include "simple_switch.h"
#include "register_access.h"

#define RA_HBH_OPTION 0x37

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
// recirculate packets go to a high priority queue, while normal pakcets go to a
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

SimpleSwitch::SimpleSwitch(bool enable_swap, port_t drop_port)
  : Switch(enable_swap),
    drop_port(drop_port),
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

  add_required_field("standard_metadata", "ra_registers");
  add_required_field("standard_metadata", "ra_tables");
  add_required_field("standard_metadata", "ra_program");

  force_arith_header("standard_metadata");
  force_arith_header("queueing_metadata");
  force_arith_header("intrinsic_metadata");

  import_primitives(this);
  init_ra_registers(0);
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
  phv->get_field("standard_metadata.ra_registers").set((char *)&ra_registers[0], 16);
  phv->get_field("standard_metadata.ra_tables").set((char *)&ra_registers[16], 16);
  phv->get_field("standard_metadata.ra_program").set((char *)&ra_registers[32], 16);
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

    char *packetDataIngress = packet->data();
    //First offset = 6 + 6
    //48 bits for dst MAC, 48 for src MAC, arrive at ethertype
    //the first Layer 1 64 bits are not included in the packet data
    //for (int i = 0; i < 20; i++) {
    //  BMLOG_DEBUG_PKT(*packet, "Byte is value {}", *(packetDataIngress + i));
    //}
    packetDataIngress += 12;
    unsigned short etype = (short)(*packetDataIngress << 8) | (short)(255 & *(packetDataIngress + 1));
    BMLOG_DEBUG_PKT(*packet, "[RA Pre-Parse] Beginning pre-parse, etype is {}", etype);
    if (etype == 34984) { // 802.1Q double, 0x88A8
      BMLOG_DEBUG_PKT(*packet, "[RA Pre-Parse] Found ethertype 802.1Q double");
      packetDataIngress += 8;
      etype = (short)(*packetDataIngress << 8) | (short)(255 & *(packetDataIngress + 1));
    }
    else if (etype == 33024) { // 802.1Q single, 0x8100
      BMLOG_DEBUG_PKT(*packet, "[RA Pre-Parse] Found ethertype 802.1Q single");
      packetDataIngress += 4;
      etype = (short)(*packetDataIngress << 8) | (short)(255 & *(packetDataIngress + 1));
    }
    if (etype == 34525) { // IPv6, 0x86DD
      BMLOG_DEBUG_PKT(*packet, "[RA Pre-Parse] Found IPv6 ethertype");
      isIPv6 = true;
      packetDataIngress += 8; // etype (2) + ver(4) + class(8) + flow (20) + len(16) = 48 bits
      unsigned char nextHeader = *packetDataIngress;
      if (nextHeader == 0) {
        BMLOG_DEBUG_PKT(*packet, "[RA Pre-Parse] Found IPv6 HBH Options");
        hasHBHOtions = true;
        packetDataIngress += 34; // nextHeader(8) + hops(8) + src(128) + dst(128) + nextHeader(8) = 280 bits
        unsigned short hbhLength = ((unsigned short)(*packetDataIngress) * 8) + 8; //length is 8-octet units beyond the first 8
        char *start = packetDataIngress;
        packetDataIngress += 1;
        BMLOG_DEBUG_PKT(*packet, "[RA Pre-Parse] HBH Options have length {:d}", hbhLength);
        while (packetDataIngress < start + hbhLength) {
          BMLOG_DEBUG_PKT(*packet, "[RA Pre-Parse] Looping: At {:p}, under {:p}, type is {:x}", (void *)packetDataIngress, (void *)(start + hbhLength), *packetDataIngress);
          if (*packetDataIngress == RA_HBH_OPTION) {
            hasRAExtension = true;
            BMLOG_DEBUG_PKT(*packet, "[RA Pre-Parse] Found RA HBH Option");
            break;
          }
          else if (*packetDataIngress == 0) {
            packetDataIngress += 1;
          }
          else {
            packetDataIngress += 1;
            packetDataIngress += ((unsigned short)(*packetDataIngress) * 8) + 1;
          }
        }
      }
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
      copy_field_list_and_set_type(packet, packet_copy,
                                   PKT_INSTANCE_TYPE_RESUBMIT,
                                   field_list_id);
      RegisterAccess::clear_all(packet_copy.get());
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
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
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
        if (config.mgid_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
          multicast(packet_copy.get(), config.mgid);
        }
        if (config.egress_port_valid) {
          BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                          config.egress_port);
          RegisterAccess::clear_all(packet_copy.get());
          enqueue(config.egress_port, std::move(packet_copy));
        }
      }
    }

    // TODO(antonin): should not be done like this in egress pipeline
    port_t egress_spec = f_egress_spec.get_uint();
    if (egress_spec == drop_port) {  // drop packet
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of egress");
      continue;
    }

    deparser->deparse(packet.get());
    char *packetDataEgress = packet->data();
    char *packetDataEgressStart = packetDataEgress;
    packetDataEgress += 12; // dst(48) + src(48) = 96 bits
    unsigned short etype = (short)(*packetDataEgress << 8) | (short)(255 & *(packetDataEgress + 1));

    if (hasRAExtension) {
      BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Beginning post-deparse with existing RA extension");
      if (etype == 34984) { // 802.1Q double, 0x88A8
        BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Found ethertype 802.1Q double");
        packetDataEgress += 8;
        etype = (short)(*packetDataEgress << 8) | (short)(255 & *(packetDataEgress + 1));
      }
      else if (etype == 33024) { // 802.1Q single, 0x8100
        BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Found ethertype 802.1Q single");
        packetDataEgress += 4;
        etype = (short)(*packetDataEgress << 8) | (short)(255 & *(packetDataEgress + 1));
      }
      if (etype == 34525) { // IPv6, 0x86DD
        BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Found IPv6 ethertype");
        packetDataEgress += 8; // etype(2) + ver(4) + class(8) + flow (20) + len(16) = 48 bits
        unsigned char nextHeader = *packetDataEgress;
        if (nextHeader == 0) {
          BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Found IPv6 HBH Options");
          packetDataEgress += 35; // next(8) + hops(8) + src(128) + dst(128) + next(8) = 280 bits
          unsigned char hbhLength = ((unsigned short)(*packetDataEgress) * 8) + 8; //length is 8-octet units beyond the first 8
          char *start = packetDataEgress;
          packetDataEgress += 1;
          BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] HBH Options have length {:d}", hbhLength);
          while (packetDataEgress < start + hbhLength) {
            BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Looping: At {:p}, under {:p}, type is {:x}", (void *)packetDataEgress, (void *)(start + hbhLength), *packetDataEgress);
            if (*packetDataEgress == RA_HBH_OPTION) {
              packetDataEgress += 6; // type(8) + len(8) + padding(32) = 48 bits
              unsigned char delta = packetDataEgress - start;
              if ((delta - 2) % 8 != 0) {
                packetDataEgress += 4;
              }
              unsigned char route[16];
              BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Inserting RA data");
              for (int q = 0; q < (int)(nb_ra_registers); q++) {
                memcpy(packetDataEgress, &ra_registers[16*q], 16);
                memcpy(&route[0], packetDataEgress + 48, 16);
                for (int r = 0; r < 16; r++) {
                  route[r] ^= ra_registers[16*q + r];
                }
                memcpy(packetDataEgress + 48, &route[0], 16);
                packetDataEgress += 16;
              }
              break;
            }
            else if (*packetDataEgress == 0) {
              packetDataEgress += 1;
            }
            else {
              packetDataEgress += 1;
              packetDataEgress += ((unsigned short)(*packetDataEgress) * 8) + 1;
            }
          }
        }
      }
    }
    else if (isIPv6) {
      BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Beginning post-deparse possibly adding new RA extension");
      size_t sizeIPData = 12;
      if (etype == 34984) { // 802.1Q double, 0x88A8
        BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Found ethertype 802.1Q double");
        sizeIPData += 8;
        packetDataEgress += 8;
        etype = (short)(*packetDataEgress << 8) | (short)(255 & *(packetDataEgress + 1));
      }
      else if (etype == 33024) { // 802.1Q single, 0x8100
        BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Found ethertype 802.1Q single");
        sizeIPData += 4;
        packetDataEgress += 4;
        etype = (short)(*packetDataEgress << 8) | (short)(255 & *(packetDataEgress + 1));
      }
      sizeIPData += 2;
      if (etype == 34525) { // IPv6, 0x86DD
        BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Found IPv6 ethertype");
        packetDataEgress += 8; // etype(16) + ver(4) + class(8) + flow (20) + len(16) = 64 bits
        unsigned char nextHeader = *packetDataEgress;
        if (nextHeader == 0) {
          BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Found IPv6 HBH Options");
          packetDataEgress += 35; // next(8) + hops(8) + src(128) + dst(128) + next(8) = 280 bits
          unsigned char hbhLength = ((unsigned short)(*packetDataEgress) * 8) + 8; //length is 8-octet units beyond the first 8
          char *start = packetDataEgress;
          packetDataEgress += 1;
          bool existsRAOption = false;
          BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] HBH Options have length {:d}", hbhLength);
          while (packetDataEgress < start + hbhLength) {
            BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Looping: At {:p}, under {:p}, type is {:x}", (void *)packetDataEgress, (void *)(start + hbhLength), *packetDataEgress);
            if (*packetDataEgress == RA_HBH_OPTION) {
              existsRAOption = true;
              packetDataEgress += 6; // type(8) + len(8) + padding(32) = 48 bits
              unsigned char delta = packetDataEgress - start;
              if ((delta - 2) % 8 != 0) {
                packetDataEgress += 4;
              }
              unsigned char route[16];
              BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Inserting RA data");
              for (int q = 0; q < (int)(nb_ra_registers); q++) {
                memcpy(packetDataEgress, &ra_registers[16*q], 16);
                memcpy(&route[0], packetDataEgress + 48, 16);
                for (int r = 0; r < 16; r++) {
                  route[r] ^= ra_registers[16*q + r];
                }
                memcpy(packetDataEgress + 48, &route[0], 16);
                packetDataEgress += 16;
              }
              break;
            }
            else if (*packetDataEgress == 0) {
              packetDataEgress += 1;
            }
            else {
              packetDataEgress += 1;
              packetDataEgress += ((unsigned short)(*packetDataEgress) * 8) + 1;
            }
          }
          if (!existsRAOption) {
            packetDataEgress = start;
            *packetDataEgress += 13; // 16 * 6 + 8 = 104 octects / 8 = 13 8-octets length for RA HBH option
            sizeIPData += 40 + hbhLength; // size of IPv6 header + old size of HBH options
            packetDataEgress = start - 37; // back to IPv6 length
            unsigned short length = (*packetDataEgress << 8) | *(packetDataEgress + 1);
            length += 104;
            *packetDataEgress = (char)(length >> 8);
            *(packetDataEgress + 1) = (char)((length << 8) >> 8);
            packetDataEgress = start + hbhLength;
            char *packetDataNew = packet->prepend(104);
            BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Moving {} bytes of data to new start {:p} from old start {:p}",
                            sizeIPData, (void *)(packetDataNew), (void *)(packetDataEgressStart));
            memmove(packetDataNew, packetDataEgressStart, sizeIPData);
            packetDataEgress = packetDataNew + sizeIPData;
            BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Inserting RA HBH option at {:p}", (void *)(packetDataEgress));
            *packetDataEgress = 1;
            *(packetDataEgress + 1) = 0;
            *(packetDataEgress + 2) = RA_HBH_OPTION;
            *(packetDataEgress + 3) = 100;
            packetDataEgress += 4;
            for (int q = 0; q < (int)(nb_ra_registers); q++) {
              memcpy(packetDataEgress, &ra_registers[16*q], 16);
              memcpy(packetDataEgress + 48, &ra_registers[16*q], 16);
              packetDataEgress += 16;
            }
          }
        }
        else {
          sizeIPData += 40; // size of IPv6 header
          *packetDataEgress = 0;
          packetDataEgress -= 2; // get back to len
          unsigned short length = (*packetDataEgress << 8) | *(packetDataEgress + 1);
          length += 104; // size of RA HBH Option
          *packetDataEgress = (char)(length >> 8);
          *(packetDataEgress + 1) = (char)((length << 8) >> 8);
          packetDataEgress += 36; // len(16) + next(8) + hops(8) + src(128) + dst(128) = 280 bits
          char *packetDataNew = packet->prepend(104);
          BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Moving {} bytes of data to new start {:p} from old start {:p}",
                          sizeIPData, (void *)(packetDataNew), (void *)(packetDataEgressStart));
          memmove(packetDataNew, packetDataEgressStart, sizeIPData);
          packetDataEgress = packetDataNew + sizeIPData;
          BMLOG_DEBUG_PKT(*packet, "[RA Post-Deparse] Inserting RA IPv6 Extension header at {:p}", (void *)(packetDataEgress));
          *packetDataEgress = nextHeader; // Set next in HBH options to what was in IPv6
          *(packetDataEgress + 1) = 12; // Set length of HBH options (13 - 1)
          *(packetDataEgress + 2) = RA_HBH_OPTION;
          *(packetDataEgress + 3) = 100;
          packetDataEgress += 4;
          for (int q = 0; q < (int)(nb_ra_registers); q++) {
            memcpy(packetDataEgress, &ra_registers[16*q], 16);
            memcpy(packetDataEgress + 48, &ra_registers[16*q], 16);
            packetDataEgress += 16;
          }
        }
      }
    }

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

    output_buffer.push_front(std::move(packet));
  }
}
