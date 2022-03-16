#include <rte_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_cycles.h>
#include <cassert>
#include "lifecycle.hpp"
#include "ring.h"
#include <iostream>
#include <cmath>

namespace PACKETGRABBER {

  static inline void grab(uint8_t port_id, uint16_t queue_id, struct rte_ring* ring) {
    constexpr size_t batchsize = 1;

    const uint64_t tsc_hz = rte_get_tsc_hz(); // cycles per second
    const double tsc_hz_nsec = (double) tsc_hz / (1000.0 * 1000.0 * 1000.0); // cycles per ns

    struct rte_mbuf* bufs[batchsize] __rte_cache_aligned; // mbuf pointer array
    unsigned int num_occupied = 0;
    // uint64_t last_hw_timestamp = 0;
    // uint64_t last_sw_timestamp = (uint64_t) ((double) rte_rdtsc() / tsc_hz_nsec);
    // uint8_t is_first_packet = 0;
    // uint64_t counter = 0;
    while(libmoon::is_running(0)) {
      uint16_t rx_cnt = rte_eth_rx_burst(port_id, queue_id, bufs, batchsize);
      if (rx_cnt == 0) {
       	rte_delay_us(2);
      }
      // we need the floating point op, tsc / (tsc_hz / 10^6) is too imprecise
      // (and tsc * 10^6 overflows after a few hours)
      uint64_t sw_timestamp_batch = (uint64_t) ((double) rte_rdtsc() / tsc_hz_nsec);
      for (uint16_t i = 0; i < rx_cnt; ++ i) {
	 // uint32_t* timestamp32 = (uint32_t*)((uint8_t*)bufs[i]->buf_addr + bufs[i]->data_off + bufs[i]->pkt_len - 8);
	 // uint64_t hw_timestamp = timestamp32[0] + timestamp32[1] * pow(10, 9);
	 // std::cout << "RX[" << i << "/" << rx_cnt - 1 << "]: Software Timestamp: " << sw_timestamp_batch << " Hardware Timestamp " << hw_timestamp << std::endl;
	 // timestamp sometimes jumps by ~3 seconds on ixgbe (in less than a few milliseconds wall-clock time)
	 // we fallback to software timestamps in this case
	 // we need to take care though, as software and hardware clocks have different epochs
	 // + i to still guarantee for strong monotonous timestamps
	 // if (not is_first_packet and hw_timestamp - last_hw_timestamp > pow(10, 9)) {
	 //   bufs[i]->timestamp = last_hw_timestamp + (sw_timestamp_batch - last_sw_timestamp) + i;
	 // } else {
	 //   bufs[i]->timestamp = sw_timestamp;
	 // }
	 // bufs[i]->timestamp = counter;
	bufs[i]->timestamp = sw_timestamp_batch;
	 if (rte_ring_sp_enqueue(ring, bufs[i]) != 0) {
	   std::cout << "Packet loss, no space in queue available" << std::endl;
	 }
	 // last_hw_timestamp = hw_timestamp;
	 // counter += 1;
      }
      // last_sw_timestamp = sw_timestamp_batch;
      // is_first_packet = 1;
    }
  }

}

extern "C" {
  void grab(uint8_t port_id, uint16_t queue_id, struct rte_ring* ring){
    PACKETGRABBER::grab(port_id, queue_id, ring);
  }
}
