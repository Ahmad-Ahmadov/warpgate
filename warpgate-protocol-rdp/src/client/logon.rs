//! The target's own sign-in state, as reported by the Save Session Info PDU
//! ([MS-RDPBCGR] 2.2.10.1), and the account the session logged on as.
//!
//! Until the target reports a logon, the session is sitting at the target's sign-in screen,
//! which is where a user types credentials that Warpgate never sees, and which the recording
//! must not keep.
//!
//! The report names the account (Logon Info Version 1 or 2: the domain, or computer, and the
//! account name). Warpgate compares it with the account the user may use on the target
//! ([`LogonIdentity`]) and ends a session that logged on as any other: that is what stops a
//! user from typing another account's name and password into the target's sign-in screen, or
//! its lock screen, and working as that account through Warpgate. The target sends a report
//! for every logon, the first and any later one (MS-RDPBCGR 3.3.5.10.1), because IronRDP asks
//! for them (`INFO_LOGONNOTIFY`). IronRDP keeps the PDU itself private, so the frame is read
//! here before IronRDP processes it.

use ironrdp_pdu::Action;
use ironrdp_pdu::mcs::{SendDataIndicationCtx, decode_send_data_indication};
use ironrdp_pdu::rdp::headers::{IoChannelPdu, ShareDataPdu, ShareDataPduType, decode_io_channel};
use ironrdp_pdu::rdp::session_info::{InfoData, LogonInfoVersion1, LogonInfoVersion2};
use tracing::{debug, info, warn};
use uuid::Uuid;
use warpgate_common::TargetSessionId;
use warpgate_common::audit::AuditEvent;
use warpgate_core::LogonState;
use warpgate_core::rdp_account::LogonIdentity;

/// What a Save Session Info PDU says about a logon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LogonReport {
    /// A logon, with the account it is (`domain` is the computer's name for a local account)
    /// and the remote session's id.
    Named {
        domain: String,
        username: String,
        session_id: u32,
    },
    /// A logon whose account the target did not name (Plain Notify), or that could not be
    /// read.
    Unnamed,
    /// Not a logon: extended logon information (an auto-reconnect cookie, logon errors).
    Other,
}

/// The logon reports in a frame from the target: none for anything but a Save Session Info
/// PDU on the I/O channel. A frame can carry several Share Control PDUs, one after another.
pub(crate) fn logon_reports(action: Action, frame: &[u8], io_channel_id: u16) -> Vec<LogonReport> {
    if action != Action::X224 {
        return vec![];
    }
    let Ok(ctx) = decode_send_data_indication(frame) else {
        return vec![];
    };
    if ctx.channel_id != io_channel_id {
        return vec![];
    }
    let data = ctx.user_data;
    let mut reports = Vec::new();
    let mut offset = 0usize;
    while offset + 2 <= data.len() {
        let length = usize::from(u16::from_le_bytes([data[offset], data[offset + 1]]));
        if length == 0 || offset + length > data.len() {
            // Not Share Control PDUs (a PDU with a basic security header, say), which IronRDP
            // reads whole, as is done here.
            if offset == 0 {
                reports.extend(report_of(SendDataIndicationCtx {
                    initiator_id: ctx.initiator_id,
                    channel_id: ctx.channel_id,
                    user_data: data,
                }));
            }
            break;
        }
        reports.extend(report_of(SendDataIndicationCtx {
            initiator_id: ctx.initiator_id,
            channel_id: ctx.channel_id,
            user_data: &data[offset..offset + length],
        }));
        offset += length;
    }
    reports
}

fn report_of(ctx: SendDataIndicationCtx<'_>) -> Option<LogonReport> {
    let IoChannelPdu::Data(share) = decode_io_channel(ctx).ok()? else {
        return None;
    };
    match share.pdu {
        ShareDataPdu::SaveSessionInfo(info) => Some(match info.info_data {
            InfoData::LogonInfoV1(LogonInfoVersion1 { logon_info })
            | InfoData::LogonInfoV2(LogonInfoVersion2 { logon_info }) => LogonReport::Named {
                domain: clean(&logon_info.domain_name),
                username: clean(&logon_info.user_name),
                session_id: logon_info.session_id,
            },
            InfoData::PlainNotify => LogonReport::Unnamed,
            InfoData::LogonExtended(_) => LogonReport::Other,
        }),
        // Warpgate does not negotiate bulk compression, so a target should not compress this;
        // one that does reports a logon that cannot be read here.
        ShareDataPdu::Compressed {
            pdu_type: ShareDataPduType::SaveSessionInfo,
            ..
        } => Some(LogonReport::Unnamed),
        _ => None,
    }
}

/// A name as the PDU carries it: fixed-size fields can leave their padding in.
fn clean(name: &str) -> String {
    name.trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_owned()
}

/// A session that logged on as an account the user may not use on the target.
#[derive(Debug)]
pub(crate) struct RefusedLogon {
    pub reported: String,
}

impl std::fmt::Display for RefusedLogon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the target logged on as {}, an account the user may not use there",
            self.reported
        )
    }
}

impl std::error::Error for RefusedLogon {}

pub(crate) struct LogonWatcher {
    pub target_session_id: TargetSessionId,
    pub target_id: Uuid,
    pub target_name: String,
    pub user_id: Uuid,
    pub username: String,
    pub sign_in: LogonState,
    /// The account the session must log on as. `None` for an interactive-logon target with
    /// stored credentials, which leaves the account to whoever is at the target's own
    /// sign-in screen: its logons are recorded, but not held to an account.
    pub allowed: Option<LogonIdentity>,
}

impl LogonWatcher {
    /// Take the target's report of a logon. An error ends the session: the target logged on
    /// as an account the user may not use there.
    pub fn observe(&mut self, report: LogonReport) -> Result<(), RefusedLogon> {
        match report {
            LogonReport::Other => {
                debug!("Target sent extended logon info");
                Ok(())
            }
            LogonReport::Unnamed => {
                // A target names the account of a logon whenever it differs from the one the
                // connection signed in with, and whenever the client asked to be told, as
                // this one does (MS-RDPBCGR 3.3.5.10.1); so an unnamed logon is the account
                // Warpgate signed in with.
                if self.allowed.is_some() {
                    info!("The target reported a logon without naming the account");
                }
                self.logged_on(None, None);
                Ok(())
            }
            LogonReport::Named {
                domain,
                username,
                session_id,
            } => {
                let reported = if domain.is_empty() {
                    username.clone()
                } else {
                    format!("{domain}\\{username}")
                };
                if let Some(allowed) = &mut self.allowed
                    && !allowed.admits(&domain, &username)
                {
                    warn!(
                        user = %self.username,
                        target_account = %reported,
                        allowed_account = %allowed.account(),
                        "The target logged on as an account the user may not use; ending the session"
                    );
                    AuditEvent::TargetLogonRefused {
                        session_id: self.target_session_id.0,
                        target_id: self.target_id,
                        target_name: self.target_name.clone(),
                        user_id: self.user_id,
                        username: self.username.clone(),
                        target_account: reported.clone(),
                        allowed_account: allowed.account().to_owned(),
                    }
                    .emit();
                    return Err(RefusedLogon { reported });
                }
                self.logged_on(Some(reported), Some(session_id));
                Ok(())
            }
        }
    }

    fn logged_on(&self, target_account: Option<String>, target_session_id: Option<u32>) {
        self.sign_in.mark_logged_on();
        AuditEvent::TargetLogon {
            session_id: self.target_session_id.0,
            target_id: self.target_id,
            target_name: self.target_name.clone(),
            user_id: self.user_id,
            username: self.username.clone(),
            target_account,
            target_session_id,
        }
        .emit();
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::mcs::{McsMessage, SendDataIndication};
    use ironrdp_pdu::rdp::headers::{
        CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, StreamPriority,
    };
    use ironrdp_pdu::rdp::session_info::{InfoType, LogonInfo, SaveSessionInfoPdu};
    use ironrdp_pdu::x224::X224;
    use warpgate_core::rdp_account::WindowsAccount;

    use super::*;

    const IO_CHANNEL: u16 = 1003;

    /// A Save Session Info PDU naming `domain` and `username`, as a target frames it.
    fn logon_frame(channel_id: u16, info_data: InfoData) -> Vec<u8> {
        let info_type = match &info_data {
            InfoData::LogonInfoV1(_) => InfoType::Logon,
            InfoData::LogonInfoV2(_) => InfoType::LogonLong,
            InfoData::PlainNotify => InfoType::PlainNotify,
            InfoData::LogonExtended(_) => InfoType::LogonExtended,
        };
        let share = ShareControlHeader {
            share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
                share_data_pdu: ShareDataPdu::SaveSessionInfo(SaveSessionInfoPdu {
                    info_type,
                    info_data,
                }),
                stream_priority: StreamPriority::Medium,
                compression_flags: CompressionFlags::empty(),
                compression_type: ironrdp_pdu::rdp::client_info::CompressionType::K8,
            }),
            pdu_source: 1002,
            share_id: 0x0001_03ea,
        };
        let user_data = encode_vec(&share).unwrap();
        encode_vec(&X224(McsMessage::SendDataIndication(SendDataIndication {
            initiator_id: 1002,
            channel_id,
            user_data: std::borrow::Cow::Owned(user_data),
        })))
        .unwrap()
    }

    fn logon_info(domain: &str, username: &str) -> LogonInfo {
        LogonInfo {
            session_id: 7,
            user_name: username.into(),
            domain_name: domain.into(),
        }
    }

    fn watcher(allowed: Option<LogonIdentity>) -> LogonWatcher {
        LogonWatcher {
            target_session_id: TargetSessionId(Uuid::nil()),
            target_id: Uuid::nil(),
            target_name: "server".into(),
            user_id: Uuid::nil(),
            username: "alice".into(),
            sign_in: LogonState::at_logon_screen(),
            allowed,
        }
    }

    #[test]
    fn a_logon_report_names_the_account() {
        let frame = logon_frame(
            IO_CHANNEL,
            InfoData::LogonInfoV2(LogonInfoVersion2 {
                logon_info: logon_info("CORP", "alice"),
            }),
        );
        assert_eq!(
            logon_reports(Action::X224, &frame, IO_CHANNEL),
            vec![LogonReport::Named {
                domain: "CORP".into(),
                username: "alice".into(),
                session_id: 7,
            }]
        );
        // Not the I/O channel, or not a slow-path frame: not a logon report.
        assert!(logon_reports(Action::X224, &frame, IO_CHANNEL + 1).is_empty());
        assert!(logon_reports(Action::FastPath, &frame, IO_CHANNEL).is_empty());

        let plain = logon_frame(IO_CHANNEL, InfoData::PlainNotify);
        assert_eq!(
            logon_reports(Action::X224, &plain, IO_CHANNEL),
            vec![LogonReport::Unnamed]
        );
    }

    fn named(domain: &str, username: &str) -> LogonReport {
        LogonReport::Named {
            domain: domain.into(),
            username: username.into(),
            session_id: 1,
        }
    }

    #[test]
    fn a_logon_as_another_account_is_refused() {
        let alice = LogonIdentity::for_account(&WindowsAccount {
            username: "alice".into(),
            domain: Some("CORP".into()),
        });

        let mut session = watcher(Some(alice.clone()));
        assert!(session.observe(named("corp", "Alice")).is_ok());
        assert!(!session.sign_in.still_at_logon_screen());
        // Signed out and back in on the lock screen as somebody else.
        let refused = session.observe(named("CORP", "administrator")).unwrap_err();
        assert_eq!(refused.reported, format!("CORP{}administrator", '\\'));

        // The same name on the target itself is another account.
        let mut local = watcher(Some(alice));
        assert!(local.observe(named("SRV01", "alice")).is_err());
        assert!(local.sign_in.still_at_logon_screen());
        // Extended logon information is no logon.
        assert!(local.observe(LogonReport::Other).is_ok());
        assert!(local.sign_in.still_at_logon_screen());

        // Nothing to hold the logon to: recorded, never refused.
        let mut open = watcher(None);
        assert!(
            open.observe(LogonReport::Named {
                domain: "CORP".into(),
                username: "administrator".into(),
                session_id: 1,
            })
            .is_ok()
        );
        assert!(!open.sign_in.still_at_logon_screen());
    }

    #[test]
    fn names_lose_their_padding() {
        assert_eq!(clean("CORP\0\0 "), "CORP");
        assert_eq!(clean(" alice"), "alice");
    }
}
