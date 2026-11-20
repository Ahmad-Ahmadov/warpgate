//! The sign-in screen, for a viewer that connected without a password.
//!
//! The listener negotiates TLS-only security, not NLA: CredSSP would need every user's
//! password up front to check the client's NTLM response, which a gateway that keeps only
//! password hashes, or binds to LDAP, does not have. So credentials come from the Client
//! Info PDU. FreeRDP-based clients (MobaXterm, Remmina) always put the password there. mstsc
//! puts one there only when it holds a saved credential: otherwise, as against any server
//! that does not negotiate NLA, it asks for nothing and expects the server to sign the user
//! in on screen, as Windows' own logon screen does. Warpgate used to take that empty
//! password for a wrong one, refusing the connection and counting a failed attempt, so mstsc
//! could not connect at all without "Allow me to save credentials". It now shows this form,
//! and checks what is typed into it exactly as it checks a password from the Client Info PDU.
//!
//! The same form, with the account filled in and fixed, asks for the viewer's own domain
//! password for a target that signs in with it ([`SignInScreen::for_domain_password`]).

use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use tokio::time::{Instant, MissedTickBehavior, interval, sleep_until};
use warpgate_common::consts::TICKET_SELECTOR_PREFIX;
use warpgate_core::domain_account::{MAX_DOMAIN_PASSWORD_CHARS, Zeroize as _};
use warpgate_core::{DesktopInput, Scancode};
use warpgate_desktop_ui::{self as ui, SignInField, SignInNotice, SignInPrompt};

use super::hold_screen::{HOLD_RENDER_INTERVAL, HoldPainter};
use super::protocol::{Event as ServerEvent, Input as ServerInput};

/// Refused sign-ins a connection may make before it is refused itself, as for one-time
/// passwords. Each also counts towards the user's and the address's lockout.
pub(super) const MAX_SIGN_IN_ATTEMPTS: usize = 3;

/// How long the form waits for the viewer, across all of its attempts.
pub(super) const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(180);

/// The longest username and password the form takes: what the Client Info PDU carries
/// (MS-RDPBCGR 2.2.1.11.1.1).
const MAX_FIELD_CHARS: usize = 256;

/// What a refused attempt is told, whatever the reason. The check reports a wrong password
/// and a wrong target differently, but only after it has checked the password, so telling
/// them apart here would confirm a password to anyone who pairs it with a made-up target.
const REFUSED: &str = "Sign-in failed. Check the username, target and password";
const CHECKING: &str = "Signing in...";
const CHECKING_DOMAIN_PASSWORD: &str = "Checking your domain password...";

/// Whether the viewer has to sign in on the form: it sent no password, and its username is
/// not a ticket, which needs none.
pub(super) fn needs_sign_in(username: &str, password: &str) -> bool {
    password.is_empty() && !username.starts_with(TICKET_SELECTOR_PREFIX)
}

/// The credentials submitted on the form.
pub(super) struct Submission {
    pub username: String,
    pub password: String,
}

/// What showing the form came to.
pub(super) enum SignInStep {
    Submitted(Submission),
    /// The viewer disconnected.
    Disconnected,
    /// The viewer did not sign in within [`SIGN_IN_TIMEOUT`].
    TimedOut,
}

/// The sign-in form on the viewer's screen.
pub(super) struct SignInScreen {
    form: Form,
    /// The target, when the form asks for the viewer's domain password to sign in to it
    /// rather than for Warpgate credentials.
    domain_target: Option<String>,
    keyboard: Keyboard,
    painter: HoldPainter,
    /// Whether the form has changed since it was last painted. It is painted only then:
    /// anyone who can reach the listener can hold this screen open without signing in, and
    /// every frame is a full-screen encode, so an idle form must cost nothing.
    dirty: bool,
    /// Mouse buttons last reported, to tell a press from a drag.
    buttons: u8,
    /// The viewer's clipboard text, which its RDP client sends when the session starts and
    /// whenever it changes. Pasted on Ctrl+V or Shift+Insert, for password managers.
    clipboard: Option<String>,
    /// Whether the clipboard text was pasted into the form, so is most likely a password.
    pasted: bool,
    failures: usize,
    deadline: Instant,
}

impl SignInScreen {
    /// A form with `username` filled in: what the viewer's Client Info PDU carried, as
    /// mstsc sends the username it was given even when it has no password.
    pub(super) fn new(username: &str, screen: ui::Screen) -> Self {
        Self::with_form(Form::new(username), None, screen)
    }

    /// A form asking for the viewer's own domain password, to sign in to `target` as
    /// `account`. The account is shown and cannot be edited: it is the directory's, not the
    /// viewer's to choose. A submission's `username` is that account, unchanged.
    pub(super) fn for_domain_password(target: &str, account: &str, screen: ui::Screen) -> Self {
        Self::with_form(
            Form::for_domain_password(account),
            Some(target.to_owned()),
            screen,
        )
    }

    fn with_form(form: Form, domain_target: Option<String>, screen: ui::Screen) -> Self {
        Self {
            form,
            domain_target,
            keyboard: Keyboard::default(),
            painter: HoldPainter::new(screen),
            dirty: true,
            buttons: 0,
            clipboard: None,
            pasted: false,
            failures: 0,
            deadline: Instant::now() + SIGN_IN_TIMEOUT,
        }
    }

    /// Show the form until the viewer submits it, disconnects or runs out of time. Like
    /// the hold screens, it tracks the size the viewer settles on in `screen` meanwhile.
    pub(super) async fn next_submission(
        &mut self,
        events: &mut UnboundedReceiver<ServerEvent>,
        server_in_tx: &Sender<ServerInput>,
        screen: &mut ui::Screen,
    ) -> Result<SignInStep> {
        // Changes are painted at most once a tick, however fast the viewer types.
        let mut ticker = interval(HOLD_RENDER_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let deadline = sleep_until(self.deadline);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                () = &mut deadline => return Ok(SignInStep::TimedOut),
                event = events.recv() => {
                    let Some(event) = event else {
                        return Ok(SignInStep::Disconnected);
                    };
                    if let Some(edit) = self.edit(event, screen) {
                        self.dirty = true;
                        if let Some(submission) = self.apply(edit) {
                            return Ok(SignInStep::Submitted(submission));
                        }
                    }
                }
                _ = ticker.tick(), if self.dirty => self.paint(server_in_tx).await?,
            }
        }
    }

    /// Show that the submitted credentials are being checked. That can take a moment (an
    /// LDAP bind, say), and the form is not repainted meanwhile.
    pub(super) async fn show_checking(&mut self, server_in_tx: &Sender<ServerInput>) -> Result<()> {
        self.form.notice = Some(SignInNotice::Info(if self.domain_target.is_some() {
            CHECKING_DOMAIN_PASSWORD
        } else {
            CHECKING
        }));
        self.paint(server_in_tx).await
    }

    /// Report a refused attempt. Returns `false` once the viewer has used up its
    /// [`MAX_SIGN_IN_ATTEMPTS`].
    pub(super) fn refused(&mut self) -> bool {
        self.refused_with(REFUSED)
    }

    /// Report a refused attempt with `notice`, which says why. For the domain password,
    /// where the directory's answer is the viewer's own business: their password, their
    /// account. Returns `false` once the viewer has used up its [`MAX_SIGN_IN_ATTEMPTS`].
    pub(super) fn refused_with(&mut self, notice: &'static str) -> bool {
        self.failures += 1;
        self.form.focus = SignInField::Password;
        self.form.notice = Some(SignInNotice::Error(notice));
        self.dirty = true;
        self.failures < MAX_SIGN_IN_ATTEMPTS
    }

    /// Show `notice` as the form's last word, before the session is ended: no further
    /// attempt is taken.
    pub(super) async fn show_final_error(
        &mut self,
        server_in_tx: &Sender<ServerInput>,
        notice: &'static str,
    ) -> Result<()> {
        self.form.notice = Some(SignInNotice::Error(notice));
        self.paint(server_in_tx).await
    }

    /// The viewer's clipboard text, for the target: the form took the event that would have
    /// carried it there. `None` if the viewer sent none, or pasted it into the form, as it
    /// is then most likely the Warpgate password, which must not reach the target or the
    /// session recording.
    pub(super) fn into_clipboard(self) -> Option<String> {
        self.clipboard.filter(|_| !self.pasted)
    }

    /// Read one viewer event: a size to track, lock state, clipboard text, or input.
    fn edit(&mut self, event: ServerEvent, screen: &mut ui::Screen) -> Option<Edit> {
        match event {
            ServerEvent::Size { width, height } | ServerEvent::ResizeRequest { width, height } => {
                *screen = ui::Screen { width, height };
                self.painter.set_screen(*screen);
                // A new size, or a reactivation at the old one, leaves the viewer without
                // the form until it is painted again.
                self.dirty = true;
                None
            }
            ServerEvent::KeyboardSync {
                caps_lock,
                num_lock,
            } => {
                self.keyboard.sync(caps_lock, num_lock);
                None
            }
            ServerEvent::Input(DesktopInput::Key {
                scancode: Some(scancode),
                down,
                ..
            }) => self.keyboard.scancode(scancode, down),
            ServerEvent::Input(DesktopInput::Key {
                keysym: Some(unit),
                scancode: None,
                down: true,
            }) => unicode(unit),
            ServerEvent::Input(DesktopInput::Pointer { x, y, buttons }) => {
                let pressed = buttons & !self.buttons;
                self.buttons = buttons;
                if pressed & 1 == 0 {
                    return None;
                }
                ui::sign_in_field_at(*screen, x, y).map(Edit::Focus)
            }
            ServerEvent::Input(DesktopInput::Clipboard(text)) => {
                self.clipboard = Some(text);
                self.pasted = false;
                None
            }
            // A second set of credentials never comes: the RDP server asks once. Dropping
            // its reply is a refusal.
            ServerEvent::Input(_) | ServerEvent::AuthRequest { .. } => None,
        }
    }

    fn apply(&mut self, edit: Edit) -> Option<Submission> {
        if edit == Edit::Paste {
            if let Some(clipboard) = &self.clipboard {
                self.pasted = true;
                for c in pasted(clipboard).chars() {
                    self.form.apply(Edit::Type(c));
                }
            }
            return None;
        }
        self.form.apply(edit)
    }

    async fn paint(&mut self, server_in_tx: &Sender<ServerInput>) -> Result<()> {
        self.dirty = false;
        let prompt = self.form.prompt();
        let domain_target = self.domain_target.as_deref();
        self.painter
            .paint(server_in_tx, |screen, _tick| match domain_target {
                None => ui::render_sign_in(screen, &prompt),
                Some(target) => ui::render_domain_password(
                    screen,
                    &ui::DomainPasswordPrompt {
                        target,
                        account: prompt.username,
                        password_len: prompt.password_len,
                        notice: prompt.notice,
                    },
                ),
            })
            .await
    }
}

/// What a paste types: the text's first line, without control characters. A password
/// copied from a password manager is a single line; a trailing line break is not part of it.
fn pasted(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

/// One keystroke's or click's effect on the form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Edit {
    Type(char),
    Backspace,
    /// Escape: empty the focused field.
    Clear,
    Next,
    Previous,
    Focus(SignInField),
    Paste,
    Submit,
}

/// The form's content. The password is kept only until it is submitted, and wiped if the
/// form goes away with one typed.
struct Form {
    username: String,
    password: String,
    focus: SignInField,
    notice: Option<SignInNotice<'static>>,
    /// The username is an account the form was given, not one to type: the focus stays on
    /// the password, and only a password is asked for.
    account_fixed: bool,
}

impl Drop for Form {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl Form {
    fn new(username: &str) -> Self {
        let username: String = username.chars().take(MAX_FIELD_CHARS).collect();
        // A username that already names its target is most likely right, which leaves the
        // password to type.
        let focus = if has_target(&username) {
            SignInField::Password
        } else {
            SignInField::Username
        };
        Self {
            username,
            password: String::new(),
            focus,
            notice: None,
            account_fixed: false,
        }
    }

    fn for_domain_password(account: &str) -> Self {
        Self {
            username: account.to_owned(),
            // Room for the longest password up front, so typing it never reallocates and
            // leaves a copy of its beginning behind in freed memory.
            password: String::with_capacity(MAX_DOMAIN_PASSWORD_CHARS * 4),
            focus: SignInField::Password,
            notice: None,
            account_fixed: true,
        }
    }

    const fn field_mut(&mut self) -> &mut String {
        match self.focus {
            SignInField::Username => &mut self.username,
            SignInField::Password => &mut self.password,
        }
    }

    fn apply(&mut self, edit: Edit) -> Option<Submission> {
        match edit {
            Edit::Type(c) => {
                self.notice = None;
                let field = self.field_mut();
                if field.chars().count() < MAX_FIELD_CHARS {
                    field.push(c);
                }
            }
            Edit::Backspace => {
                self.notice = None;
                self.field_mut().pop();
            }
            Edit::Clear => {
                self.notice = None;
                self.field_mut().clear();
            }
            Edit::Next | Edit::Previous | Edit::Focus(_) if self.account_fixed => {}
            Edit::Next | Edit::Previous => {
                self.focus = match self.focus {
                    SignInField::Username => SignInField::Password,
                    SignInField::Password => SignInField::Username,
                };
            }
            Edit::Focus(field) => self.focus = field,
            // Pasting is the screen's: it holds the clipboard.
            Edit::Paste => {}
            Edit::Submit => return self.submit(),
        }
        None
    }

    /// The credentials to check, or `None` with the form told what is missing.
    fn submit(&mut self) -> Option<Submission> {
        if self.account_fixed {
            if self.password.is_empty() {
                self.notice = Some(SignInNotice::Error("Enter your domain password"));
                return None;
            }
            // Swapped for another buffer with room for a whole password, for a retry.
            let password = String::with_capacity(MAX_DOMAIN_PASSWORD_CHARS * 4);
            return Some(Submission {
                username: self.username.clone(),
                password: std::mem::replace(&mut self.password, password),
            });
        }
        let username = signed_in_name(&self.username);
        let ticket = username.starts_with(TICKET_SELECTOR_PREFIX);
        let missing = if username.is_empty() {
            Some((SignInField::Username, "Enter your username"))
        } else if !ticket && !has_target(username) {
            Some((SignInField::Username, "Enter the username as user:target"))
        } else if !ticket && self.password.is_empty() {
            Some((SignInField::Password, "Enter your password"))
        } else {
            None
        };
        if let Some((field, notice)) = missing {
            self.focus = field;
            self.notice = Some(SignInNotice::Error(notice));
            return None;
        }
        Some(Submission {
            username: username.to_owned(),
            password: std::mem::take(&mut self.password),
        })
    }

    fn prompt(&self) -> SignInPrompt<'_> {
        SignInPrompt {
            username: &self.username,
            password_len: self.password.chars().count(),
            focus: self.focus,
            notice: self.notice,
        }
    }
}

/// Whether `username` names a target too, read the way [`AuthSelector`] reads it.
///
/// [`AuthSelector`]: warpgate_common::auth::AuthSelector
fn has_target(username: &str) -> bool {
    let separator = if username.contains('#') { '#' } else { ':' };
    username
        .split_once(separator)
        .is_some_and(|(user, target)| !user.is_empty() && !target.is_empty())
}

/// What the typed username is looked up by: trimmed, and with a `DOMAIN\` prefix dropped.
/// mstsc and FreeRDP split that prefix off into the Client Info PDU's domain field, which
/// Warpgate ignores, so `CORP\alice:server` signs in the same typed here as typed there.
fn signed_in_name(username: &str) -> &str {
    let username = username.trim();
    username
        .split_once('\\')
        .map_or(username, |(_domain, user)| user)
}

/// A character a viewer sent as Unicode, as mstsc does for input from an IME or the
/// on-screen keyboard.
fn unicode(unit: u32) -> Option<Edit> {
    match unit {
        0x08 => Some(Edit::Backspace),
        0x09 => Some(Edit::Next),
        0x0a | 0x0d => Some(Edit::Submit),
        0x1b => Some(Edit::Clear),
        // A lone UTF-16 surrogate is not a character, and the form takes no control codes.
        _ => char::from_u32(unit)
            .filter(|c| !c.is_control())
            .map(Edit::Type),
    }
}

/// Modifier and lock state, tracked from the viewer's keystrokes.
#[derive(Clone, Copy, Debug)]
struct Keyboard {
    shift_left: bool,
    shift_right: bool,
    ctrl_left: bool,
    ctrl_right: bool,
    alt_left: bool,
    alt_right: bool,
    caps_lock: bool,
    num_lock: bool,
}

impl Default for Keyboard {
    fn default() -> Self {
        Self {
            shift_left: false,
            shift_right: false,
            ctrl_left: false,
            ctrl_right: false,
            alt_left: false,
            alt_right: false,
            caps_lock: false,
            // On, as on most keyboards, until the viewer's Synchronize event says otherwise.
            num_lock: true,
        }
    }
}

impl Keyboard {
    const fn shift(&self) -> bool {
        self.shift_left || self.shift_right
    }

    const fn ctrl(&self) -> bool {
        self.ctrl_left || self.ctrl_right
    }

    const fn alt(&self) -> bool {
        self.alt_left || self.alt_right
    }

    const fn sync(&mut self, caps_lock: bool, num_lock: bool) {
        self.caps_lock = caps_lock;
        self.num_lock = num_lock;
    }

    /// The flag a modifier key holds, if `code` is one.
    const fn modifier(&mut self, code: u8, extended: bool) -> Option<&mut bool> {
        Some(match (code, extended) {
            (0x2a, false) => &mut self.shift_left,
            (0x36, false) => &mut self.shift_right,
            (0x1d, false) => &mut self.ctrl_left,
            (0x1d, true) => &mut self.ctrl_right,
            (0x38, false) => &mut self.alt_left,
            (0x38, true) => &mut self.alt_right,
            _ => return None,
        })
    }

    /// Apply a PC/AT set-1 scancode, the form mstsc and FreeRDP send keys in. Characters
    /// are read as on a US English keyboard: what the viewer's layout puts on each key is
    /// not something the form can know, and the screen says so.
    fn scancode(&mut self, Scancode { code, extended }: Scancode, down: bool) -> Option<Edit> {
        if let Some(held) = self.modifier(code, extended) {
            *held = down;
            return None;
        }
        if !down {
            return None;
        }
        match (code, extended) {
            (0x3a, false) => {
                self.caps_lock = !self.caps_lock;
                None
            }
            (0x45, _) => {
                self.num_lock = !self.num_lock;
                None
            }
            (0x0e, false) => Some(Edit::Backspace),
            (0x0f, false) if self.shift() => Some(Edit::Previous),
            (0x0f, false) => Some(Edit::Next),
            // Enter, on the main block and on the keypad.
            (0x1c, _) => Some(Edit::Submit),
            (0x01, false) => Some(Edit::Clear),
            // Up and Down move between the fields.
            (0x48, true) => Some(Edit::Focus(SignInField::Username)),
            (0x50, true) => Some(Edit::Focus(SignInField::Password)),
            (0x2f, false) if self.ctrl() && !self.alt() => Some(Edit::Paste),
            (0x52, true) if self.shift() => Some(Edit::Paste),
            // A chord types nothing. On a US keyboard Right Alt is Alt, not AltGr.
            _ if self.ctrl() || self.alt() => None,
            (0x35, true) => Some(Edit::Type('/')),
            (code, false) => self.character(code).map(Edit::Type),
            _ => None,
        }
    }

    /// The character `code` types on a US English keyboard.
    fn character(&self, code: u8) -> Option<char> {
        if let Some((c, needs_num_lock)) = keypad_key(code) {
            // Without Num Lock the keypad's digits are cursor keys.
            return (self.num_lock || !needs_num_lock).then_some(c);
        }
        let (plain, shifted) = us_key(code)?;
        let upper = if plain.is_ascii_lowercase() {
            self.shift() != self.caps_lock
        } else {
            self.shift()
        };
        Some(if upper { shifted } else { plain })
    }
}

/// A keypad key's character, and whether it types it only with Num Lock on.
const fn keypad_key(code: u8) -> Option<(char, bool)> {
    Some(match code {
        0x37 => ('*', false),
        0x4a => ('-', false),
        0x4e => ('+', false),
        0x47 => ('7', true),
        0x48 => ('8', true),
        0x49 => ('9', true),
        0x4b => ('4', true),
        0x4c => ('5', true),
        0x4d => ('6', true),
        0x4f => ('1', true),
        0x50 => ('2', true),
        0x51 => ('3', true),
        0x52 => ('0', true),
        0x53 => ('.', true),
        _ => return None,
    })
}

/// A key's characters on a US English keyboard, without and with Shift.
const fn us_key(code: u8) -> Option<(char, char)> {
    Some(match code {
        0x02 => ('1', '!'),
        0x03 => ('2', '@'),
        0x04 => ('3', '#'),
        0x05 => ('4', '$'),
        0x06 => ('5', '%'),
        0x07 => ('6', '^'),
        0x08 => ('7', '&'),
        0x09 => ('8', '*'),
        0x0a => ('9', '('),
        0x0b => ('0', ')'),
        0x0c => ('-', '_'),
        0x0d => ('=', '+'),
        0x10 => ('q', 'Q'),
        0x11 => ('w', 'W'),
        0x12 => ('e', 'E'),
        0x13 => ('r', 'R'),
        0x14 => ('t', 'T'),
        0x15 => ('y', 'Y'),
        0x16 => ('u', 'U'),
        0x17 => ('i', 'I'),
        0x18 => ('o', 'O'),
        0x19 => ('p', 'P'),
        0x1a => ('[', '{'),
        0x1b => (']', '}'),
        0x1e => ('a', 'A'),
        0x1f => ('s', 'S'),
        0x20 => ('d', 'D'),
        0x21 => ('f', 'F'),
        0x22 => ('g', 'G'),
        0x23 => ('h', 'H'),
        0x24 => ('j', 'J'),
        0x25 => ('k', 'K'),
        0x26 => ('l', 'L'),
        0x27 => (';', ':'),
        0x28 => ('\'', '"'),
        0x29 => ('`', '~'),
        0x2b => ('\\', '|'),
        0x2c => ('z', 'Z'),
        0x2d => ('x', 'X'),
        0x2e => ('c', 'C'),
        0x2f => ('v', 'V'),
        0x30 => ('b', 'B'),
        0x31 => ('n', 'N'),
        0x32 => ('m', 'M'),
        0x33 => (',', '<'),
        0x34 => ('.', '>'),
        0x35 => ('/', '?'),
        0x39 => (' ', ' '),
        // The extra key of ISO keyboards, next to Left Shift.
        0x56 => ('\\', '|'),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::{UnboundedSender, channel, unbounded_channel};

    use super::*;

    fn screen() -> ui::Screen {
        ui::Screen {
            width: 1024,
            height: 768,
        }
    }

    /// A viewer-side sink for the painted frames, drained so painting never blocks.
    fn viewer() -> Sender<ServerInput> {
        let (tx, mut rx) = channel(16);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        tx
    }

    fn key(code: u8, extended: bool, down: bool) -> ServerEvent {
        ServerEvent::Input(DesktopInput::Key {
            keysym: None,
            scancode: Some(Scancode { code, extended }),
            down,
        })
    }

    fn press(events: &UnboundedSender<ServerEvent>, code: u8, extended: bool) {
        events.send(key(code, extended, true)).unwrap();
        events.send(key(code, extended, false)).unwrap();
    }

    /// Type `text` on a US keyboard, the way mstsc sends it: scancodes, Shift held around
    /// the characters that need it.
    fn type_text(events: &UnboundedSender<ServerEvent>, text: &str) {
        for c in text.chars() {
            let (code, shifted) = (0..=0x7f)
                .find_map(|code| {
                    let (plain, shifted) = us_key(code)?;
                    if plain == c {
                        Some((code, false))
                    } else if shifted == c {
                        Some((code, true))
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("{c:?} is not on a US keyboard"));
            if shifted {
                events.send(key(0x2a, false, true)).unwrap();
            }
            press(events, code, false);
            if shifted {
                events.send(key(0x2a, false, false)).unwrap();
            }
        }
    }

    fn typed(keyboard: &mut Keyboard, code: u8) -> Option<char> {
        let edit = keyboard.scancode(
            Scancode {
                code,
                extended: false,
            },
            true,
        );
        keyboard.scancode(
            Scancode {
                code,
                extended: false,
            },
            false,
        );
        match edit {
            Some(Edit::Type(c)) => Some(c),
            _ => None,
        }
    }

    async fn submitted(
        sign_in: &mut SignInScreen,
        events: &mut UnboundedReceiver<ServerEvent>,
    ) -> Submission {
        let mut screen = screen();
        match sign_in
            .next_submission(events, &viewer(), &mut screen)
            .await
            .unwrap()
        {
            SignInStep::Submitted(submission) => submission,
            SignInStep::Disconnected => panic!("the form reported a disconnect"),
            SignInStep::TimedOut => panic!("the form timed out"),
        }
    }

    #[test]
    fn only_a_missing_password_needs_the_form() {
        assert!(needs_sign_in("alice:server", ""));
        assert!(needs_sign_in("", ""));
        assert!(!needs_sign_in("alice:server", "secret"));
        // A ticket stands in for both.
        assert!(!needs_sign_in("ticket-0123abcd", ""));
    }

    #[test]
    fn keys_type_what_a_us_keyboard_says() {
        let mut keyboard = Keyboard::default();
        assert_eq!(typed(&mut keyboard, 0x1e), Some('a'));
        assert_eq!(typed(&mut keyboard, 0x02), Some('1'));
        assert_eq!(typed(&mut keyboard, 0x28), Some('\''));
        assert_eq!(typed(&mut keyboard, 0x39), Some(' '));

        keyboard.scancode(
            Scancode {
                code: 0x36,
                extended: false,
            },
            true,
        );
        assert_eq!(typed(&mut keyboard, 0x1e), Some('A'));
        assert_eq!(typed(&mut keyboard, 0x02), Some('!'));
        assert_eq!(typed(&mut keyboard, 0x28), Some('"'));
        keyboard.scancode(
            Scancode {
                code: 0x36,
                extended: false,
            },
            false,
        );
        assert_eq!(typed(&mut keyboard, 0x1e), Some('a'));
    }

    /// Caps Lock, whether toggled here or already on when the session started, changes
    /// letters only, and Shift undoes it.
    #[test]
    fn caps_lock_changes_letters_only() {
        let mut keyboard = Keyboard::default();
        keyboard.sync(true, true);
        assert_eq!(typed(&mut keyboard, 0x1e), Some('A'));
        assert_eq!(typed(&mut keyboard, 0x02), Some('1'));
        keyboard.scancode(
            Scancode {
                code: 0x2a,
                extended: false,
            },
            true,
        );
        assert_eq!(typed(&mut keyboard, 0x1e), Some('a'));
        assert_eq!(typed(&mut keyboard, 0x02), Some('!'));

        let mut keyboard = Keyboard::default();
        assert_eq!(typed(&mut keyboard, 0x3a), None);
        assert_eq!(typed(&mut keyboard, 0x1e), Some('A'));
        assert_eq!(typed(&mut keyboard, 0x3a), None);
        assert_eq!(typed(&mut keyboard, 0x1e), Some('a'));
    }

    #[test]
    fn the_keypad_types_digits_with_num_lock_only() {
        let mut keyboard = Keyboard::default();
        assert_eq!(typed(&mut keyboard, 0x4f), Some('1'));
        assert_eq!(typed(&mut keyboard, 0x53), Some('.'));
        keyboard.sync(false, false);
        assert_eq!(typed(&mut keyboard, 0x4f), None);
        assert_eq!(typed(&mut keyboard, 0x4a), Some('-'));
        assert_eq!(
            keyboard.scancode(
                Scancode {
                    code: 0x35,
                    extended: true,
                },
                true
            ),
            Some(Edit::Type('/'))
        );
    }

    /// Shortcuts must not type their letter into a password, and the nav cluster, which
    /// repeats the keypad's codes under an E0 prefix, must not type digits.
    #[test]
    fn chords_and_navigation_keys_type_nothing() {
        let mut keyboard = Keyboard::default();
        keyboard.scancode(
            Scancode {
                code: 0x1d,
                extended: false,
            },
            true,
        );
        assert_eq!(typed(&mut keyboard, 0x2e), None); // Ctrl+C
        keyboard.scancode(
            Scancode {
                code: 0x1d,
                extended: false,
            },
            false,
        );
        keyboard.scancode(
            Scancode {
                code: 0x38,
                extended: true,
            },
            true,
        );
        assert_eq!(typed(&mut keyboard, 0x10), None); // Right Alt+Q
        keyboard.scancode(
            Scancode {
                code: 0x38,
                extended: true,
            },
            false,
        );

        for code in [0x47u8, 0x49, 0x4b, 0x4d, 0x4f, 0x51, 0x52, 0x53] {
            assert_eq!(
                keyboard.scancode(
                    Scancode {
                        code,
                        extended: true
                    },
                    true
                ),
                None,
                "extended scancode {code:#x}"
            );
        }
    }

    #[test]
    fn control_keys_edit_the_form() {
        let mut keyboard = Keyboard::default();
        let mut down = |code, extended| keyboard.scancode(Scancode { code, extended }, true);
        assert_eq!(down(0x0e, false), Some(Edit::Backspace));
        assert_eq!(down(0x0f, false), Some(Edit::Next));
        assert_eq!(down(0x1c, false), Some(Edit::Submit));
        assert_eq!(down(0x1c, true), Some(Edit::Submit));
        assert_eq!(down(0x01, false), Some(Edit::Clear));
        assert_eq!(down(0x48, true), Some(Edit::Focus(SignInField::Username)));
        assert_eq!(down(0x50, true), Some(Edit::Focus(SignInField::Password)));
        assert_eq!(down(0x2a, false), None);
        assert_eq!(down(0x0f, false), Some(Edit::Previous));
        assert_eq!(down(0x52, true), Some(Edit::Paste));
    }

    #[test]
    fn unicode_input_types_any_character() {
        assert_eq!(unicode(u32::from('ə')), Some(Edit::Type('ə')));
        assert_eq!(unicode(u32::from('Ж')), Some(Edit::Type('Ж')));
        assert_eq!(unicode(0x08), Some(Edit::Backspace));
        assert_eq!(unicode(0x0d), Some(Edit::Submit));
        assert_eq!(unicode(0x1b), Some(Edit::Clear));
        assert_eq!(unicode(0xd83d), None); // half of a surrogate pair
        assert_eq!(unicode(0x07), None);
    }

    #[test]
    fn a_username_with_its_target_leaves_the_password_to_type() {
        assert_eq!(Form::new("alice:server").focus, SignInField::Password);
        assert_eq!(Form::new("alice#server").focus, SignInField::Password);
        assert_eq!(Form::new("alice").focus, SignInField::Username);
        assert_eq!(Form::new("").focus, SignInField::Username);
    }

    #[test]
    fn an_incomplete_form_says_what_is_missing() {
        let mut form = Form::new("");
        assert!(form.apply(Edit::Submit).is_none());
        assert_eq!(form.focus, SignInField::Username);
        assert_eq!(
            form.notice,
            Some(SignInNotice::Error("Enter your username"))
        );

        let mut form = Form::new("alice");
        assert!(form.apply(Edit::Submit).is_none());
        assert_eq!(
            form.notice,
            Some(SignInNotice::Error("Enter the username as user:target"))
        );

        let mut form = Form::new("alice:server");
        assert!(form.apply(Edit::Submit).is_none());
        assert_eq!(form.focus, SignInField::Password);
        assert_eq!(
            form.notice,
            Some(SignInNotice::Error("Enter your password"))
        );
        // Typing clears the complaint.
        form.apply(Edit::Type('x'));
        assert_eq!(form.notice, None);
    }

    #[test]
    fn submitting_hands_over_the_password_and_forgets_it() {
        let mut form = Form::new("alice:server");
        for c in "s3cret!".chars() {
            form.apply(Edit::Type(c));
        }
        form.apply(Edit::Backspace);
        let submission = form.apply(Edit::Submit).unwrap();
        assert_eq!(submission.username, "alice:server");
        assert_eq!(submission.password, "s3cret");
        assert!(form.password.is_empty());
        assert_eq!(form.prompt().password_len, 0);
    }

    #[test]
    fn a_domain_prefix_is_dropped_as_mstsc_drops_it() {
        assert_eq!(signed_in_name(" CORP\\alice:server "), "alice:server");
        assert_eq!(
            signed_in_name("alice@corp.example:server"),
            "alice@corp.example:server"
        );
        assert_eq!(signed_in_name("alice:server"), "alice:server");
    }

    #[test]
    fn a_ticket_needs_no_password_or_target() {
        let mut form = Form::new("ticket-0123abcd");
        let submission = form.apply(Edit::Submit).unwrap();
        assert_eq!(submission.username, "ticket-0123abcd");
        assert!(submission.password.is_empty());
    }

    #[test]
    fn fields_are_bounded() {
        let mut form = Form::new(&"u".repeat(1000));
        assert_eq!(form.username.chars().count(), MAX_FIELD_CHARS);
        form.focus = SignInField::Password;
        for _ in 0..1000 {
            form.apply(Edit::Type('p'));
        }
        assert_eq!(form.password.chars().count(), MAX_FIELD_CHARS);
    }

    #[test]
    fn a_paste_types_the_first_line() {
        assert_eq!(pasted("s3cret\r\n"), "s3cret");
        assert_eq!(pasted("first\nsecond"), "first");
        assert_eq!(pasted("tab\there"), "tabhere");
        assert_eq!(pasted(""), "");
    }

    /// mstsc without a saved credential: the username it was given is filled in, the
    /// password is typed in scancodes, and Enter submits exactly what was typed.
    #[tokio::test]
    async fn typing_the_password_signs_in() {
        let (tx, mut events) = unbounded_channel();
        let mut sign_in = SignInScreen::new("alice:server", screen());

        type_text(&tx, "Pa$$w0rd 1");
        press(&tx, 0x1c, false);

        let submission = submitted(&mut sign_in, &mut events).await;
        assert_eq!(submission.username, "alice:server");
        assert_eq!(submission.password, "Pa$$w0rd 1");
    }

    #[tokio::test]
    async fn both_fields_can_be_typed_and_clicked_between() {
        let (tx, mut events) = unbounded_channel();
        let mut sign_in = SignInScreen::new("", screen());

        type_text(&tx, "bob:db");
        press(&tx, 0x0f, false); // Tab
        type_text(&tx, "hunter2");
        // Back to the username with a click, to fix a typo in it.
        let (x, y) = ui::sign_in_field_center(screen(), SignInField::Username);
        tx.send(ServerEvent::Input(DesktopInput::Pointer {
            x,
            y,
            buttons: 1,
        }))
        .unwrap();
        tx.send(ServerEvent::Input(DesktopInput::Pointer {
            x,
            y,
            buttons: 0,
        }))
        .unwrap();
        type_text(&tx, "1");
        press(&tx, 0x1c, false);

        let submission = submitted(&mut sign_in, &mut events).await;
        assert_eq!(submission.username, "bob:db1");
        assert_eq!(submission.password, "hunter2");
    }

    #[tokio::test]
    async fn the_viewers_clipboard_pastes_into_the_focused_field() {
        let (tx, mut events) = unbounded_channel();
        let mut sign_in = SignInScreen::new("alice:server", screen());

        tx.send(ServerEvent::Input(DesktopInput::Clipboard(
            "c0pied-secret\r\n".into(),
        )))
        .unwrap();
        tx.send(key(0x1d, false, true)).unwrap(); // Ctrl
        press(&tx, 0x2f, false); // V
        tx.send(key(0x1d, false, false)).unwrap();
        press(&tx, 0x1c, false);

        let submission = submitted(&mut sign_in, &mut events).await;
        assert_eq!(submission.password, "c0pied-secret");
        // Pasted into the form, so most likely the password: it must not go on to the
        // target, or into the session recording.
        assert_eq!(sign_in.into_clipboard(), None);
    }

    /// Clipboard text the viewer did not paste into the form goes on to the target, as it
    /// would have without the form.
    #[tokio::test]
    async fn an_unpasted_clipboard_is_kept_for_the_target() {
        let (tx, mut events) = unbounded_channel();
        let mut sign_in = SignInScreen::new("alice:server", screen());

        tx.send(ServerEvent::Input(DesktopInput::Clipboard("notes".into())))
            .unwrap();
        type_text(&tx, "typed");
        press(&tx, 0x1c, false);

        assert_eq!(submitted(&mut sign_in, &mut events).await.password, "typed");
        assert_eq!(sign_in.into_clipboard().as_deref(), Some("notes"));
    }

    #[tokio::test]
    async fn caps_lock_on_at_connect_is_honoured() {
        let (tx, mut events) = unbounded_channel();
        let mut sign_in = SignInScreen::new("alice:server", screen());

        tx.send(ServerEvent::KeyboardSync {
            caps_lock: true,
            num_lock: true,
        })
        .unwrap();
        press(&tx, 0x1e, false); // a
        press(&tx, 0x1c, false);

        assert_eq!(submitted(&mut sign_in, &mut events).await.password, "A");
    }

    /// The target has to be dialled at the size the viewer is showing.
    #[tokio::test]
    async fn a_size_settled_meanwhile_is_kept() {
        let (tx, mut events) = unbounded_channel();
        let mut sign_in = SignInScreen::new("alice:server", screen());
        let mut screen = screen();

        tx.send(ServerEvent::Size {
            width: 1920,
            height: 1080,
        })
        .unwrap();
        type_text(&tx, "x");
        press(&tx, 0x1c, false);

        assert!(matches!(
            sign_in
                .next_submission(&mut events, &viewer(), &mut screen)
                .await
                .unwrap(),
            SignInStep::Submitted(_)
        ));
        assert_eq!((screen.width, screen.height), (1920, 1080));
    }

    #[tokio::test]
    async fn a_departed_viewer_ends_the_form() {
        let (tx, mut events) = unbounded_channel::<ServerEvent>();
        let mut sign_in = SignInScreen::new("alice:server", screen());
        drop(tx);

        assert!(matches!(
            sign_in
                .next_submission(&mut events, &viewer(), &mut screen())
                .await
                .unwrap(),
            SignInStep::Disconnected
        ));
    }

    /// An unauthenticated viewer must not hold the connection open indefinitely.
    #[tokio::test(start_paused = true)]
    async fn the_form_times_out() {
        let (_tx, mut events) = unbounded_channel::<ServerEvent>();
        // Small, as the form is repainted for every 100 ms of the wait.
        let mut screen = ui::Screen {
            width: 200,
            height: 200,
        };
        let mut sign_in = SignInScreen::new("alice:server", screen);

        let started = Instant::now();
        assert!(matches!(
            sign_in
                .next_submission(&mut events, &viewer(), &mut screen)
                .await
                .unwrap(),
            SignInStep::TimedOut
        ));
        assert!(started.elapsed() >= SIGN_IN_TIMEOUT);
    }

    #[tokio::test]
    async fn the_form_is_painted_while_it_waits() {
        let (_tx, mut events) = unbounded_channel::<ServerEvent>();
        let (viewer_tx, mut viewer_rx) = channel(16);
        let mut sign_in = SignInScreen::new("alice:server", screen());

        let _ = tokio::time::timeout(
            Duration::from_millis(250),
            sign_in.next_submission(&mut events, &viewer_tx, &mut screen()),
        )
        .await;

        assert!(matches!(
            viewer_rx.try_recv(),
            Ok(ServerInput::Frame { .. })
        ));
    }

    /// The form is up before the viewer has signed in, for anyone who can reach the
    /// listener, and every frame is a full-screen encode: it must not keep painting while
    /// nothing changes.
    #[tokio::test(start_paused = true)]
    async fn the_form_is_painted_only_when_it_changes() {
        let frames = |viewer_rx: &mut tokio::sync::mpsc::Receiver<ServerInput>| {
            std::iter::from_fn(|| viewer_rx.try_recv().ok())
                .filter(|input| matches!(input, ServerInput::Frame { .. }))
                .count()
        };
        let (tx, mut events) = unbounded_channel::<ServerEvent>();
        let (viewer_tx, mut viewer_rx) = channel(16);
        let mut screen = ui::Screen {
            width: 200,
            height: 200,
        };
        let mut sign_in = SignInScreen::new("alice:server", screen);

        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            sign_in.next_submission(&mut events, &viewer_tx, &mut screen),
        )
        .await;
        assert_eq!(frames(&mut viewer_rx), 1, "idle, after its first frame");

        press(&tx, 0x1e, false);
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            sign_in.next_submission(&mut events, &viewer_tx, &mut screen),
        )
        .await;
        assert_eq!(frames(&mut viewer_rx), 1, "once for the keystroke");
    }

    #[test]
    fn attempts_run_out() {
        let mut sign_in = SignInScreen::new("alice:server", screen());
        for _ in 1..MAX_SIGN_IN_ATTEMPTS {
            assert!(sign_in.refused());
        }
        assert!(!sign_in.refused());
        assert_eq!(sign_in.form.notice, Some(SignInNotice::Error(REFUSED)));
        assert_eq!(sign_in.form.focus, SignInField::Password);
    }

    /// The domain password form asks for the password alone: the account is the directory's,
    /// and no key or click moves the focus to it, let alone edits it.
    #[test]
    fn the_domain_account_cannot_be_edited() {
        let mut form = Form::for_domain_password(r"CORP\alice");
        for edit in [
            Edit::Next,
            Edit::Previous,
            Edit::Focus(SignInField::Username),
        ] {
            form.apply(edit);
            assert_eq!(form.focus, SignInField::Password);
        }
        assert!(form.apply(Edit::Submit).is_none());
        assert_eq!(
            form.notice,
            Some(SignInNotice::Error("Enter your domain password"))
        );
        for c in "s3cret".chars() {
            form.apply(Edit::Type(c));
        }
        let submission = form.apply(Edit::Submit).unwrap();
        assert_eq!(submission.username, r"CORP\alice");
        assert_eq!(submission.password, "s3cret");
        assert!(form.password.is_empty());
        assert!(form.password.capacity() >= MAX_DOMAIN_PASSWORD_CHARS);
    }

    #[test]
    fn a_refused_domain_password_says_why() {
        let mut sign_in =
            SignInScreen::for_domain_password("server", "alice@corp.example.com", screen());
        assert!(sign_in.refused_with("The domain password is incorrect"));
        assert_eq!(
            sign_in.form.notice,
            Some(SignInNotice::Error("The domain password is incorrect"))
        );
        assert!(sign_in.refused_with("The domain password is incorrect"));
        assert!(!sign_in.refused_with("The domain password is incorrect"));
    }

    #[tokio::test]
    async fn typing_the_domain_password_submits_it() {
        let (tx, mut events) = unbounded_channel();
        let mut sign_in =
            SignInScreen::for_domain_password("server", "alice@corp.example.com", screen());
        // Tab first: it must not move the typing into the account.
        press(&tx, 0x0f, false);
        type_text(&tx, "pa55word");
        press(&tx, 0x1c, false);

        let submission = submitted(&mut sign_in, &mut events).await;
        assert_eq!(submission.username, "alice@corp.example.com");
        assert_eq!(submission.password, "pa55word");
    }
}
