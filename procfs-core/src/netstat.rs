use crate::ProcResult;
#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};
use std::io::BufRead;

/// Represents the data from `/proc/net/netstat`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct Netstat {
    // TcpExt
    /// The number of SYN cookies sent
    pub tcp_ext_syncookies_sent: u64,
    /// The number of SYN cookies received
    pub tcp_ext_syncookies_recv: u64,
    // The number of invalid SYN cookies received
    pub tcp_ext_syncookies_failed: u64,
    /// The number of resets received for embryonic SYN_RECV sockets
    pub tcp_ext_embryonic_rsts: u64,
    /// The number of packets pruned from receive queue because of socket buffer overrun
    pub tcp_ext_prune_called: u64,
    /// The number of packets pruned from receive queue
    pub tcp_ext_rcv_pruned: u64,
    /// The number of packets dropped from out-of-order queue because of socket buffer overrun
    pub tcp_ext_ofo_pruned: u64,
    /// The number of ICMP packets dropped because they were out-of-window
    pub tcp_ext_out_of_window_icmps: u64,
    /// The number of ICMP packets dropped because socket was locked
    pub tcp_ext_lock_dropped_icmps: u64,
    // The number of arp packets filtered
    pub tcp_ext_arp_filter: u64,
    /// The number of TCP sockets finished time wait in fast timer
    pub tcp_ext_tw: u64,
    /// The number of time wait sockets recycled by timestamp
    pub tcp_ext_tw_recycled: u64,
    /// The number of TCP sockets finished time wait in slow timer
    pub tcp_ext_tw_killed: u64,
    /// The number of active connections rejected because of timestamp
    pub tcp_ext_paws_active: u64,
    /// The number of packets rejected in established connections because of timestamp
    pub tcp_ext_paws_estab: u64,
    /// The number of delayed acks sent
    pub tcp_ext_delayed_acks: u64,
    /// The number of delayed acks further delayed because of locked socket
    pub tcp_ext_delayed_ack_locked: u64,
    /// The number of quick ack mode was activated times
    pub tcp_ext_delayed_ack_lost: u64,
    /// The number of times the listen queue of a socket overflowed
    pub tcp_ext_listen_overflows: u64,
    /// The number of SYNs to LISTEN sockets dropped
    pub tcp_ext_listen_drops: u64,
    /// The number of packet headers predicted
    pub tcp_ext_tcp_hp_hits: u64,
    /// The number of acknowledgments not containing data payload received
    pub tcp_ext_tcp_pure_acks: u64,
    /// The number of predicted acknowledgments
    pub tcp_ext_tcp_hp_acks: u64,
    /// The number of times recovered from packet loss due to fast retransmit
    pub tcp_ext_tcp_reno_recovery: u64,
    //. The number of SACK retransmits failed
    pub tcp_ext_tcp_sack_recovery: u64,
    /// The number of bad SACK blocks received
    pub tcp_ext_tcp_sack_reneging: u64,
    /// The number of detected reordering times using SACK
    pub tcp_ext_tcp_sack_reorder: u64,
    /// The number of detected reordering times using Reno
    pub tcp_ext_tcp_reno_reorder: u64,
    /// The number of detected reordering times using time stamp
    pub tcp_ext_tcp_ts_reorder: u64,
    /// The number of congestion windows fully recovered without slow start
    pub tcp_ext_tcp_full_undo: u64,
    //. The number of congestion windows partially recovered using Hoe heuristic
    pub tcp_ext_tcp_partial_undo: u64,
    /// The number of congestion windows recovered without slow start by DSACK
    pub tcp_ext_tcp_dsack_undo: u64,
    /// The number of congestion windows recovered without slow start after partial ack
    pub tcp_ext_tcp_loss_undo: u64,
    /// The number of retransmits lost
    pub tcp_ext_tcp_lost_retransmit: u64,
    /// The number of RTO failed times when in TCP_CA_Disorder state, and remote end has no sack
    pub tcp_ext_tcp_reno_failures: u64,
    /// The number of RTO failed times when in TCP_CA_Disorder state, and remote end has sack
    pub tcp_ext_tcp_sack_failures: u64,
    /// The number of RTO failed times when in TCP_CA_Loss state,
    pub tcp_ext_tcp_loss_failures: u64,
    /// The number of fast retransmits
    pub tcp_ext_tcp_fast_retrans: u64,
    /// The number of retransmits in slow start
    pub tcp_ext_tcp_slow_start_retrans: u64,
    /// The number of RTO timer first timeout times
    pub tcp_ext_tcp_timeouts: u64,
    /// The number of send Tail Loss Probe (TLP) times by Probe Timeout(PTO)
    pub tcp_ext_tcp_loss_probes: u64,
    /// The number of recovery times by TLP
    pub tcp_ext_tcp_loss_probe_recovery: u64,
    /// The number of RTO failed times when in Recovery state, and remote end has no sack
    pub tcp_ext_tcp_reno_recovery_fail: u64,
    /// The number of RTO failed times when in Recovery state, and remote end has sack
    pub tcp_ext_tcp_sack_recovery_fail: u64,
    /// The number of packets collapsed in receive queue due to low socket buffer
    pub tcp_ext_tcp_rcv_collapsed: u64,
    /// The number of coalesced packets that were in the backlog queue
    pub tcp_ext_tcp_backlog_coalesce: u64,
    /// The number of DSACKs sent for old packets
    pub tcp_ext_tcp_dsack_old_sent: u64,
    /// The number of DSACKs sent for out of order packets
    pub tcp_ext_tcp_dsack_ofo_sent: u64,
    /// The number of DSACKs received
    pub tcp_ext_tcp_dsack_recv: u64,
    /// The number of DSACKs for out of order packets received
    pub tcp_ext_tcp_dsack_ofo_recv: u64,
    /// The number of connections reset due to unexpected data
    pub tcp_ext_tcp_abort_on_data: u64,
    /// The number of connections reset due to early user close
    pub tcp_ext_tcp_abort_on_close: u64,
    /// The number of connections aborted due to memory pressure
    pub tcp_ext_tcp_abort_on_memory: u64,
    /// The number of connections aborted due to timeout
    pub tcp_ext_tcp_abort_on_timeout: u64,
    /// The number of connections aborted after user close in linger timeout
    pub tcp_ext_tcp_abort_on_linger: u64,
    /// The number of times unable to send RST due to no memory
    pub tcp_ext_tcp_abort_failed: u64,
    /// The number of TCP ran low on memory times
    pub tcp_ext_tcp_memory_pressures: u64,
    /// The number of TCP cumulative duration of memory pressure events, by ms
    pub tcp_ext_tcp_memory_pressures_chrono: u64,
    /// The number of SACKs discard
    pub tcp_ext_tcp_sack_discard: u64,
    /// The number of DSACKs ignore old
    pub tcp_ext_tcp_dsack_ignored_old: u64,
    /// The number of DSACKs ignore no undo
    pub tcp_ext_tcp_dsack_ignored_no_undo: u64,
    /// The number of fake timeouts detected by F-RTO
    pub tcp_ext_tcp_spurious_rtos: u64,
    /// The number of MD5 not found
    pub tcp_ext_tcp_md5_not_found: u64,
    /// The number of MD5 unexpected
    pub tcp_ext_tcp_md5_unexpected: u64,
    /// The number of MD5 failed
    pub tcp_ext_tcp_md5_failure: u64,
    /// The number of Sack shifted
    pub tcp_ext_tcp_sack_shifted: u64,
    /// The number of Sack merged
    pub tcp_ext_tcp_sack_merged: u64,
    /// The number of Sack shift fall back
    pub tcp_ext_tcp_sack_shift_fallback: u64,
    /// The number of Backlog drop
    pub tcp_ext_tcp_backlog_drop: u64,
    /// The number of PFmemalloc drop
    pub tcp_ext_pf_memalloc_drop: u64,
    /// The number of memalloc drop
    pub tcp_ext_tcp_min_ttl_drop: u64,
    /// The number of DeferAccept drop
    pub tcp_ext_tcp_defer_accept_drop: u64,
    /// The number of IP reverse path filter
    pub tcp_ext_ip_reverse_path_filter: u64,
    /// counter, if no more mem for TIME-WAIT struct, +1
    pub tcp_ext_tcp_time_wait_overflow: u64,
    /// The number of request full do cookies
    pub tcp_ext_tcp_req_qfull_do_cookies: u64,
    /// The number of request full drop
    pub tcp_ext_tcp_req_qfull_drop: u64,
    /// The number of retransmits failed, including FastRetrans, SlowStartRetrans
    pub tcp_ext_tcp_retrans_fail: u64,
    /// The number of times tried to coalesce the receive queue
    pub tcp_ext_tcp_rcv_coalesce: u64,
    /// The number of packets queued in OFO queue
    pub tcp_ext_tcp_ofo_queue: u64,
    /// The number of packets meant to be queued in OFO but dropped due to limits hit.
    /// the number of packets meant to be queued in OFO but dropped because socket rcvbuf
    pub tcp_ext_tcp_ofo_drop: u64,
    /// The number of packets in OFO that were merged with other packets
    pub tcp_ext_tcp_ofo_merge: u64,
    /// The number of challenge ACKs sent (RFC 5961 3.2)
    pub tcp_ext_tcp_challenge_ack: u64,
    /// The number of challenge ACKs sent in response to SYN packets
    pub tcp_ext_tcp_syn_challenge: u64,
    /// The number of successful outbound TFO connections
    pub tcp_ext_tcp_fast_open_active: u64,
    /// The number of SYN-ACK packets received that did not acknowledge data sent
    /// in the SYN packet and caused a retransmissions without SYN data.
    pub tcp_ext_tcp_fast_open_active_fail: u64,
    /// The number of successful inbound TFO connections
    pub tcp_ext_tcp_fast_open_passive: u64,
    /// The number of inbound SYN packets with TFO cookie that was invalid
    pub tcp_ext_tcp_fast_open_passive_fail: u64,
    /// The number of inbound SYN packets that will have TFO disabled because
    /// the socket has exceeded the max queue length
    pub tcp_ext_tcp_fast_open_listen_overflow: u64,
    /// The number of inbound SYN packets requesting TFO with TFO set but no cookie
    pub tcp_ext_tcp_fast_open_cookie_reqd: u64,
    /// The number of times the TFO blackhole has been enabled
    pub tcp_ext_tcp_fast_open_blackhole: u64,
    /// The number of times that the fast clone is not yet freed in tcp_transmit_skb()
    pub tcp_ext_tcp_spurious_rtx_host_queues: u64,
    ///  The number of low latency application-fetched packets
    pub tcp_ext_busy_poll_rx_packets: u64,
    /// The number of times stack detected skb was underused and its flush was deferred
    pub tcp_ext_tcp_auto_corking: u64,
    /// The number of times window went from zero to non-zero
    pub tcp_ext_tcp_from_zero_window_adv: u64,
    /// The number of times window went from non-zero to zero
    pub tcp_ext_tcp_to_zero_window_adv: u64,
    /// The number of times zero window announced
    pub tcp_ext_tcp_want_zero_window_adv: u64,
    /// The number of SYN and SYN/ACK retransmits to break down retransmissions into SYN,
    /// fast-retransmits, timeout retransmits, etc.
    pub tcp_ext_tcp_syn_retrans: u64,
    /// The number of outgoing packets with original data (excluding retransmission but including
    // data-in-SYN).
    pub tcp_ext_tcp_orig_data_sent: u64,
    /// TODO
    pub tcp_ext_tcp_hystart_train_detect: u64,
    /// TODO
    pub tcp_ext_tcp_hystart_train_cwnd: u64,
    /// TODO
    pub tcp_ext_tcp_hystart_delay_detect: u64,
    /// TODO
    pub tcp_ext_tcp_hystart_delay_cwnd: u64,
    /// TODO
    pub tcp_ext_tcp_ack_skipped_syn_recv: u64,
    /// TODO
    pub tcp_ext_tcp_ack_skipped_paws: u64,
    /// TODO
    pub tcp_ext_tcp_ack_skipped_seq: u64,
    /// The number of TCP connections in state "Fin_Wait2"
    pub tcp_ext_tcp_ack_skipped_finwait2: u64,
    /// The number of TCP connections in state "Time_Wait
    pub tcp_ext_tcp_ack_skipped_timewait: u64,
    pub tcp_ext_tcp_ack_skipped_challenge: u64,
    pub tcp_ext_tcp_win_probe: u64,
    pub tcp_ext_tcp_keep_alive: u64,
    pub tcp_ext_tcp_mtup_fail: u64,
    pub tcp_ext_tcp_mtup_success: u64,
    pub tcp_ext_tcp_delivered: u64,
    pub tcp_ext_tcp_delivered_ce: u64,
    pub tcp_ext_tcp_ack_compressed: u64,
    pub tcp_ext_tcp_zero_window_drop: u64,
    pub tcp_ext_tcp_rcv_qdrop: u64,
    pub tcp_ext_tcp_wqueue_too_big: u64,
    pub tcp_ext_tcp_fast_open_passive_alt_key: u64,
    pub tcp_ext_tcp_timeout_rehash: u64,
    pub tcp_ext_tcp_duplicate_data_rehash: u64,
    pub tcp_ext_tcp_ds_ack_recv_segs: u64,
    pub tcp_ext_tcp_ds_ack_ignored_dubious: u64,
    pub tcp_ext_tcp_migrate_req_success: u64,
    pub tcp_ext_tcp_migrate_req_failure: u64,
    pub tcp_ext_tcp_ecn_rehash: u64,
    // IpExt
    pub ip_ext_in_no_routes: u64,
    pub ip_ext_in_truncated_pkts: u64,
    /// The number of multicast packets received
    pub ip_ext_in_mcast_pkts: u64,
    /// The number of multicast packets sent
    pub ip_ext_out_mcast_pkts: u64,
    /// The number of broadcast packets received
    pub ip_ext_in_bcast_pkts: u64,
    /// The number of broadcast packets sent
    pub ip_ext_out_bcast_pkts: u64,
    /// The number of octets received
    pub ip_ext_in_octets: u64,
    /// The number of octets sent
    pub ip_ext_out_octets: u64,
    /// The number of multicast octets received
    pub ip_ext_in_mcast_octets: u64,
    /// The number of multicast octets sent
    pub ip_ext_out_mcast_octets: u64,
    /// The number of broadcast octets received
    pub ip_ext_in_bcast_octets: u64,
    /// The number of broadcast octets sent
    pub ip_ext_out_bcast_octets: u64,
    /// The count of icmp6 incsum errors
    pub ip_ext_in_csum_errors: u64,
    /// The number of packets received with NOECT
    pub ip_ext_in_no_ect_pkts: u64,
    /// The number of packets received with ECT(1)
    pub ip_ext_in_ect1_pkts: u64,
    /// The number of packets received with ECT(0)
    pub ip_ext_in_ect0_pkts: u64,
    /// The number of Congestion Experimented packets received
    pub ip_ext_in_ce_pkts: u64,
    /// The number of reassembly overlaps
    pub ip_ext_reasm_overlaps: u64,

    // MPTcpExt
    /// Multipath TCP received SYN with MP_CAPABLE
    pub mp_tcp_ext_mp_capable_syn_rx: u64,
    /// TODO
    pub mp_tcp_ext_mp_capable_syn_tx: u64,
    /// Multipath TCP received third ACK with MP_CAPABLE
    pub mp_tcp_ext_mp_capable_syn_ack_rx: u64,
    /// TODO
    pub mp_tcp_ext_mp_capable_ack_rx: u64,
    /// Multipath TCP server-side fallback during 3-way handshake
    pub mp_tcp_ext_mp_capable_fallback_ack: u64,
    /// Multipath TCP client-side fallback during 3-way handshake
    pub mp_tcp_ext_mp_capable_fallback_syn_ack: u64,
    /// TODO
    pub mp_tcp_ext_mp_fallback_token_init: u64,
    /// Multipath TCP segments retransmitted at the MPTCP-level
    pub mp_tcp_ext_mp_tcp_retrans: u64,
    /// Multipath TCP received MP_JOIN but the token was not found
    pub mp_tcp_ext_mp_join_no_token_found: u64,
    /// Multipath TCP received a SYN and MP_JOIN
    pub mp_tcp_ext_mp_join_syn_rx: u64,
    /// Multipath TCP received a SYN/ACK and MP_JOIN
    pub mp_tcp_ext_mp_join_syn_ack_rx: u64,
    /// Multipath TCP HMAC was wrong on SYN/ACK and MP_JOIN
    pub mp_tcp_ext_mp_join_syn_ack_hmac_failure: u64,
    /// Multipath TCP received an ACK and MP_JOIN
    pub mp_tcp_ext_mp_join_ack_rx: u64,
    /// Multipath TCP HMAC was wrong on ACK and MP_JOIN
    pub mp_tcp_ext_mp_join_ack_hmac_failure: u64,
    /// Multipath TCP received a new mapping that did not match the previous one
    pub mp_tcp_ext_dss_not_matching: u64,
    /// Multipath TCP received an infinite mapping
    pub mp_tcp_ext_infinite_map_rx: u64,
    /// Multipath TCP segments inserted into OFO queue tail.
    pub mp_tcp_ext_ofo_queue_tail: u64,
    // Multipath TCP segments inserted into OFO queue.
    pub mp_tcp_ext_ofo_queue: u64,
    /// Multipath TCP segments merged in OFO queue.
    pub mp_tcp_ext_ofo_merge: u64,
    /// Multipath TCP segments not in MPTCP windows
    pub mp_tcp_ext_no_dss_in_window: u64,
    /// Multipath TCP segments discarded due to duplicate DSS
    pub mp_tcp_ext_duplicate_data: u64,
    /// Multipath TCP received ADD_ADDR with echo-flag=0
    pub mp_tcp_ext_add_addr: u64,
    /// Multipath TCP received ADD_ADDR with echo-flag=1
    pub mp_tcp_ext_echo_add: u64,
    /// Multipath TCP received ADD_ADDR with a port-number
    pub mp_tcp_ext_port_add: u64,
    /// Multipath TCP dropped ADD_ADDR with a port-number
    pub mp_tcp_ext_add_addrdrop: u64,
    /// Multipath TCP received a SYN MP_JOIN with a different port-number
    pub mp_tcp_ext_mp_join_port_syn_rx: u64,
    /// Multipath TCP received a SYNACK MP_JOIN with a different port-number
    pub mp_tcp_ext_mp_join_port_syn_ack_rx: u64,
    /// Multipath TCP received an ACK MP_JOIN with a different port-number
    pub mp_tcp_ext_mp_join_port_ack_rx: u64,
    /// Multipath TCP received a SYN MP_JOIN with a mismatched port-number
    pub mp_tcp_ext_mismatchport_syn_rx: u64,
    /// Multipath TCP received an ACK MP_JOIN with a mismatched port-number
    pub mp_tcp_ext_mismatchport_ack_rx: u64,
    /// Multipath TCP RM_ADDR receives
    pub mp_tcp_ext_rm_addr: u64,
    /// Multipath TCP RM_ADDR drops
    pub mp_tcp_ext_rm_addr_drop: u64,
    /// Multipath TCP subflows removed
    pub mp_tcp_ext_rm_subflow: u64,
    /// Multipath TCP MP_PRIO transmits
    pub mp_tcp_ext_mp_prio_tx: u64,
    /// Multipath TCP MP_PRIO receives
    pub mp_tcp_ext_mp_prio_rx: u64,
    /// Incoming multipath packet dropped due to memory limit.
    pub mp_tcp_ext_rcv_pruned: u64,
    /// Multipath TCP subflows entered 'stale' status
    pub mp_tcp_ext_subflow_stale: u64,
    /// Multipath TCP subflows returned to active status after being stale
    pub mp_tcp_ext_subflow_recover: u64,
}

impl super::FromBufRead for Netstat {
    fn from_buf_read<R: BufRead>(r: R) -> ProcResult<Self> {
        fn next_group<R: BufRead>(lines: &mut std::io::Lines<R>, prefix: &str) -> ProcResult<String> {
            if cfg!(test) {
                let line = lines.next().unwrap()?;
                if !line.starts_with(prefix) {
                    return Err(build_internal_error!(format!(
                        "`{}` section not found in /proc/net/netstat",
                        prefix
                    )));
                }
                let line = lines.next().unwrap()?;
                if !line.starts_with(prefix) {
                    return Err(build_internal_error!(format!(
                        "`{}` section not found in /proc/net/netstat",
                        prefix
                    )));
                }
                Ok(line)
            } else {
                Ok(lines.nth(1).unwrap()?)
            }
        }

        fn expect_none(line: Option<&str>, msg: &str) -> ProcResult<()> {
            if cfg!(test) {
                match line {
                    Some(..) => Err(build_internal_error!(format!("`{}` section is not consumed", msg))),
                    None => Ok(()),
                }
            } else {
                Ok(())
            }
        }

        let mut lines = r.lines();
        let tcp_ext = next_group(&mut lines, "TcpExt:")?;
        let mut tcp_ext = tcp_ext.split_whitespace().skip(1);
        let ip_ext = next_group(&mut lines, "IpExt:")?;
        let mut ip_ext = ip_ext.split_whitespace().skip(1);
        let mp_tcp_ext = next_group(&mut lines, "MPTcpExt:")?;
        let mut mp_tcp_ext = mp_tcp_ext.split_whitespace().skip(1);

        let netstat = Netstat {
            // TcpExt
            tcp_ext_syncookies_sent: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_syncookies_recv: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_syncookies_failed: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_embryonic_rsts: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_prune_called: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_rcv_pruned: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_ofo_pruned: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_out_of_window_icmps: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_lock_dropped_icmps: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_arp_filter: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tw: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tw_recycled: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tw_killed: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_paws_active: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_paws_estab: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_delayed_acks: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_delayed_ack_locked: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_delayed_ack_lost: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_listen_overflows: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_listen_drops: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_hp_hits: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_pure_acks: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_hp_acks: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_reno_recovery: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_sack_recovery: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_sack_reneging: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_sack_reorder: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_reno_reorder: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ts_reorder: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_full_undo: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_partial_undo: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_dsack_undo: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_loss_undo: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_lost_retransmit: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_reno_failures: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_sack_failures: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_loss_failures: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_fast_retrans: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_slow_start_retrans: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_timeouts: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_loss_probes: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_loss_probe_recovery: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_reno_recovery_fail: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_sack_recovery_fail: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_rcv_collapsed: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_backlog_coalesce: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_dsack_old_sent: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_dsack_ofo_sent: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_dsack_recv: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_dsack_ofo_recv: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_abort_on_data: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_abort_on_close: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_abort_on_memory: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_abort_on_timeout: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_abort_on_linger: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_abort_failed: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_memory_pressures: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_memory_pressures_chrono: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_sack_discard: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_dsack_ignored_old: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_dsack_ignored_no_undo: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_spurious_rtos: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_md5_not_found: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_md5_unexpected: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_md5_failure: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_sack_shifted: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_sack_merged: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_sack_shift_fallback: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_backlog_drop: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_pf_memalloc_drop: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_min_ttl_drop: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_defer_accept_drop: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_ip_reverse_path_filter: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_time_wait_overflow: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_req_qfull_do_cookies: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_req_qfull_drop: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_retrans_fail: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_rcv_coalesce: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ofo_queue: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ofo_drop: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ofo_merge: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_challenge_ack: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_syn_challenge: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_fast_open_active: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_fast_open_active_fail: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_fast_open_passive: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_fast_open_passive_fail: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_fast_open_listen_overflow: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_fast_open_cookie_reqd: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_fast_open_blackhole: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_spurious_rtx_host_queues: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_busy_poll_rx_packets: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_auto_corking: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_from_zero_window_adv: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_to_zero_window_adv: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_want_zero_window_adv: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_syn_retrans: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_orig_data_sent: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_hystart_train_detect: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_hystart_train_cwnd: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_hystart_delay_detect: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_hystart_delay_cwnd: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ack_skipped_syn_recv: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ack_skipped_paws: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ack_skipped_seq: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ack_skipped_finwait2: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ack_skipped_timewait: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ack_skipped_challenge: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_win_probe: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_keep_alive: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_mtup_fail: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_mtup_success: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_delivered: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_delivered_ce: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ack_compressed: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_zero_window_drop: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_rcv_qdrop: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_wqueue_too_big: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_fast_open_passive_alt_key: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_timeout_rehash: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_duplicate_data_rehash: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ds_ack_recv_segs: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ds_ack_ignored_dubious: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_migrate_req_success: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_migrate_req_failure: from_str!(u64, expect!(tcp_ext.next())),
            tcp_ext_tcp_ecn_rehash: from_str!(u64, expect!(tcp_ext.next())),
            // IpExt
            ip_ext_in_no_routes: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_truncated_pkts: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_mcast_pkts: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_out_mcast_pkts: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_bcast_pkts: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_out_bcast_pkts: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_octets: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_out_octets: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_mcast_octets: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_out_mcast_octets: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_bcast_octets: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_out_bcast_octets: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_csum_errors: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_no_ect_pkts: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_ect1_pkts: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_ect0_pkts: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_in_ce_pkts: from_str!(u64, expect!(ip_ext.next())),
            ip_ext_reasm_overlaps: from_str!(u64, expect!(ip_ext.next())),
            // MPTcpExt
            mp_tcp_ext_mp_capable_syn_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_capable_syn_tx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_capable_syn_ack_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_capable_ack_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_capable_fallback_ack: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_capable_fallback_syn_ack: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_fallback_token_init: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_tcp_retrans: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_join_no_token_found: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_join_syn_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_join_syn_ack_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_join_syn_ack_hmac_failure: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_join_ack_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_join_ack_hmac_failure: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_dss_not_matching: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_infinite_map_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_ofo_queue_tail: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_ofo_queue: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_ofo_merge: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_no_dss_in_window: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_duplicate_data: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_add_addr: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_echo_add: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_port_add: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_add_addrdrop: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_join_port_syn_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_join_port_syn_ack_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_join_port_ack_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mismatchport_syn_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mismatchport_ack_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_rm_addr: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_rm_addr_drop: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_rm_subflow: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_prio_tx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_mp_prio_rx: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_rcv_pruned: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_subflow_stale: from_str!(u64, expect!(mp_tcp_ext.next())),
            mp_tcp_ext_subflow_recover: from_str!(u64, expect!(mp_tcp_ext.next())),
        };

        expect_none(tcp_ext.next(), "TcpExt")?;
        expect_none(ip_ext.next(), "IpExt")?;
        expect_none(mp_tcp_ext.next(), "MPTcpExt")?;
        Ok(netstat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netstats() {
        let data = r#"TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPHPHits TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery TCPSACKReneging TCPSACKReorder TCPRenoReorder TCPTSReorder TCPFullUndo TCPPartialUndo TCPDSACKUndo TCPLossUndo TCPLostRetransmit TCPRenoFailures TCPSackFailures TCPLossFailures TCPFastRetrans TCPSlowStartRetrans TCPTimeouts TCPLossProbes TCPLossProbeRecovery TCPRenoRecoveryFail TCPSackRecoveryFail TCPRcvCollapsed TCPBacklogCoalesce TCPDSACKOldSent TCPDSACKOfoSent TCPDSACKRecv TCPDSACKOfoRecv TCPAbortOnData TCPAbortOnClose TCPAbortOnMemory TCPAbortOnTimeout TCPAbortOnLinger TCPAbortFailed TCPMemoryPressures TCPMemoryPressuresChrono TCPSACKDiscard TCPDSACKIgnoredOld TCPDSACKIgnoredNoUndo TCPSpuriousRTOs TCPMD5NotFound TCPMD5Unexpected TCPMD5Failure TCPSackShifted TCPSackMerged TCPSackShiftFallback TCPBacklogDrop PFMemallocDrop TCPMinTTLDrop TCPDeferAcceptDrop IPReversePathFilter TCPTimeWaitOverflow TCPReqQFullDoCookies TCPReqQFullDrop TCPRetransFail TCPRcvCoalesce TCPOFOQueue TCPOFODrop TCPOFOMerge TCPChallengeACK TCPSYNChallenge TCPFastOpenActive TCPFastOpenActiveFail TCPFastOpenPassive TCPFastOpenPassiveFail TCPFastOpenListenOverflow TCPFastOpenCookieReqd TCPFastOpenBlackhole TCPSpuriousRtxHostQueues BusyPollRxPackets TCPAutoCorking TCPFromZeroWindowAdv TCPToZeroWindowAdv TCPWantZeroWindowAdv TCPSynRetrans TCPOrigDataSent TCPHystartTrainDetect TCPHystartTrainCwnd TCPHystartDelayDetect TCPHystartDelayCwnd TCPACKSkippedSynRecv TCPACKSkippedPAWS TCPACKSkippedSeq TCPACKSkippedFinWait2 TCPACKSkippedTimeWait TCPACKSkippedChallenge TCPWinProbe TCPKeepAlive TCPMTUPFail TCPMTUPSuccess TCPDelivered TCPDeliveredCE TCPAckCompressed TCPZeroWindowDrop TCPRcvQDrop TCPWqueueTooBig TCPFastOpenPassiveAltKey TcpTimeoutRehash TcpDuplicateDataRehash TCPDSACKRecvSegs TCPDSACKIgnoredDubious TCPMigrateReqSuccess TCPMigrateReqFailure TCPECNRehash
TcpExt: 0 0 0 0 0 0 0 0 0 0 396966 55 0 0 6 81787 6 420 0 0 2416841 1829474 1139837 0 1 0 0 0 0 0 0 0 0 45373 0 0 0 2 1 65419 132 2 0 0 0 2735 420 2 119 0 3650 3881 0 1542 0 0 0 0 0 0 100 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 647848 16652 0 2 5 0 0 0 0 0 0 0 0 0 0 174060 0 0 0 63877 3624491 5 92 0 0 0 0 484 0 0 0 0 59802 0 0 4202023 0 6 0 0 0 0 63876 0 119 0 0 0 0
IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets OutMcastOctets InBcastOctets OutBcastOctets InCsumErrors InNoECTPkts InECT1Pkts InECT0Pkts InCEPkts ReasmOverlaps
IpExt: 0 0 0 0 0 0 12641731550007 25277955055383 0 0 0 0 0 27423021321 0 4099 0 0
MPTcpExt: MPCapableSYNRX MPCapableSYNTX MPCapableSYNACKRX MPCapableACKRX MPCapableFallbackACK MPCapableFallbackSYNACK MPFallbackTokenInit MPTCPRetrans MPJoinNoTokenFound MPJoinSynRx MPJoinSynAckRx MPJoinSynAckHMacFailure MPJoinAckRx MPJoinAckHMacFailure DSSNotMatching InfiniteMapRx OFOQueueTail OFOQueue OFOMerge NoDSSInWindow DuplicateData AddAddr EchoAdd PortAdd AddAddrDrop MPJoinPortSynRx MPJoinPortSynAckRx MPJoinPortAckRx MismatchPortSynRx MismatchPortAckRx RmAddr RmAddrDrop RmSubflow MPPrioTx MPPrioRx RcvPruned SubflowStale SubflowRecover
MPTcpExt: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"#;
        let r = std::io::Cursor::new(data.as_bytes());
        use crate::FromRead;

        let info = Netstat::from_read(r).unwrap();
        assert_eq!(info.tcp_ext_prune_called, 0);
        assert_eq!(info.tcp_ext_delayed_acks, 81787);
        assert_eq!(info.ip_ext_in_octets, 12641731550007);
        assert_eq!(info.ip_ext_in_no_ect_pkts, 27423021321);
        assert_eq!(info.mp_tcp_ext_mp_capable_fallback_ack, 0);
        assert_eq!(info.mp_tcp_ext_mp_tcp_retrans, 0);
    }
}
