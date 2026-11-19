//! Renders the "connecting" / auth screens shown to a native desktop viewer (RDP or VNC)
#![allow(clippy::cast_precision_loss, clippy::suboptimal_flops)]

mod bouncy_ball;
mod framebuffer;
mod logo;

use std::convert::Infallible;
use std::fmt::Write;

use embedded_graphics::image::Image;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::FONT_10X20;
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{CornerRadii, PrimitiveStyle, Rectangle, RoundedRectangle};
use embedded_graphics::text::{Alignment, Text};
use framebuffer::Framebuffer;
use warpgate_common::helpers::otp::OTP_DIGITS;

/// Framebuffer size assumed before a viewer or target reports its own.
pub const DEFAULT_SCREEN_W: u16 = 1024;
pub const DEFAULT_SCREEN_H: u16 = 768;
pub const DEFAULT_SIZE: (u16, u16) = (DEFAULT_SCREEN_W, DEFAULT_SCREEN_H);

pub use self::{DEFAULT_SCREEN_H as SCREEN_H, DEFAULT_SCREEN_W as SCREEN_W};
use crate::char_boxes::draw_char_boxes;
use crate::logo::logo;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Screen {
    pub width: u16,
    pub height: u16,
}

impl Default for Screen {
    fn default() -> Self {
        Self {
            width: SCREEN_W,
            height: SCREEN_H,
        }
    }
}

const BG: Rgb888 = Rgb888::new(0x14, 0x14, 0x1a);
const FG: Rgb888 = Rgb888::new(0xc1, 0xc9, 0xe4);

pub fn render_connecting(screen: Screen, tick: u64) -> Result<Vec<u8>, Infallible> {
    render(screen, tick, "Connecting", None)
}

pub fn render_awaiting_approval(screen: Screen, tick: u64) -> Result<Vec<u8>, Infallible> {
    render(
        screen,
        tick,
        "Waiting for an administrator\nto approve this session...",
        None,
    )
}

/// The login banner, shown until the viewer acknowledges it with any key or click.
pub fn render_banner(screen: Screen, tick: u64, banner: &str) -> Result<Vec<u8>, Infallible> {
    render(
        screen,
        tick,
        &format!("{banner}\n\nPress any key to continue"),
        None,
    )
}

pub enum AuthPrompt {
    WebApproval {
        url: Option<String>,
        security_key: String,
    },
    Otp {
        entered: String,
    },
}

pub fn render_authentication(
    screen: Screen,
    tick: u64,
    prompt: &AuthPrompt,
) -> Result<Vec<u8>, Infallible> {
    match prompt {
        AuthPrompt::WebApproval { url, security_key } => {
            let mut text = String::new();
            match url {
                Some(url) => {
                    let _ = write!(
                        text,
                        "Approve this session at:\n{url}\n(has been copied to your clipboard)"
                    );
                }
                None => text.push_str("Please approve this session in Warpgate first"),
            }
            let boxes = CharBoxes {
                text: security_key,
                slots: security_key.chars().count(),
            };
            text.push_str("\n\nSecurity key:");
            render(screen, tick, &text, Some(boxes))
        }
        AuthPrompt::Otp { entered } => render(
            screen,
            tick,
            "One-time password:",
            Some(CharBoxes {
                text: entered,
                slots: OTP_DIGITS,
            }),
        ),
    }
}

/// A field of the sign-in form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInField {
    Username,
    Password,
}

/// The line under the sign-in form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInNotice<'a> {
    /// An attempt was refused, or the form was submitted incomplete.
    Error(&'a str),
    /// Progress, such as while the credentials are checked.
    Info(&'a str),
}

/// The sign-in form, shown to a native RDP viewer that connected without a password.
///
/// The password never reaches the renderer, only its length: it is drawn as asterisks.
pub struct SignInPrompt<'a> {
    pub username: &'a str,
    pub password_len: usize,
    pub focus: SignInField,
    pub notice: Option<SignInNotice<'a>>,
}

/// Width of a [`FONT_10X20`] glyph, the font every screen is drawn in.
const CHAR_W: i32 = 10;
/// Pitch of the lines of text, as in [`render`].
const LINE_H: i32 = 26;
/// Offset from the top of a line of text to its baseline.
const BASELINE: i32 = 16;
const FIELD_W: i32 = 400;
const FIELD_H: i32 = 36;
/// Room between a field's edge and its text, and around a field on a narrow screen.
const FIELD_PADDING: i32 = 10;
/// Space between a field and the label of the next one.
const FIELD_GAP: i32 = 12;

/// An unfocused field, and the hints.
const DIM: Rgb888 = Rgb888::new(0x8a, 0x92, 0xad);
const ERROR: Rgb888 = Rgb888::new(0xf2, 0x8b, 0x82);

const SIGN_IN_HINTS: [&str; 3] = [
    "Username format: user:target",
    "Tab switches fields, Enter signs in",
    "Keys are read as on a US English keyboard",
];
const SIGN_IN_HINT_LINES: i32 = 3;

/// Where everything on the sign-in form goes, for drawing it and for telling which field a
/// click landed on.
struct SignInLayout {
    logo: Point,
    /// Baselines of centred lines.
    title: Point,
    notice: Point,
    hints: Point,
    /// Baselines of the labels, at their fields' left edge.
    username_label: Point,
    password_label: Point,
    username: Rectangle,
    password: Rectangle,
}

impl SignInLayout {
    fn new(screen: Screen) -> Self {
        let (w, h) = (i32::from(screen.width), i32::from(screen.height));
        let logo_size = logo().size();
        let (logo_w, logo_h) = (
            logo_size.width.cast_signed(),
            logo_size.height.cast_signed(),
        );
        let field_w = FIELD_W.min(w - 2 * FIELD_PADDING).max(8 * CHAR_W);
        let field_x = (w - field_w) / 2;
        let field_size = Size::new(field_w.cast_unsigned(), FIELD_H.cast_unsigned());
        let cx = w / 2;

        // The title and a blank line, two labelled fields, the notice, and the hints.
        let form_h =
            2 * LINE_H + 2 * (LINE_H + FIELD_H + FIELD_GAP) + LINE_H + SIGN_IN_HINT_LINES * LINE_H;
        // Centred, but with the logo no lower than on the other screens.
        let top = ((h - logo_h - LOGO_GAP - form_h) / 2).clamp(0, LOGO_Y);

        let logo = Point::new((w - logo_w) / 2, top);
        let mut y = top + logo_h + LOGO_GAP;
        let title = Point::new(cx, y + BASELINE);
        y += 2 * LINE_H;
        let username_label = Point::new(field_x, y + BASELINE);
        y += LINE_H;
        let username = Rectangle::new(Point::new(field_x, y), field_size);
        y += FIELD_H + FIELD_GAP;
        let password_label = Point::new(field_x, y + BASELINE);
        y += LINE_H;
        let password = Rectangle::new(Point::new(field_x, y), field_size);
        y += FIELD_H + FIELD_GAP;
        let notice = Point::new(cx, y + BASELINE);
        y += LINE_H;
        let hints = Point::new(cx, y + BASELINE);

        Self {
            logo,
            title,
            notice,
            hints,
            username_label,
            password_label,
            username,
            password,
        }
    }

    const fn field(&self, field: SignInField) -> &Rectangle {
        match field {
            SignInField::Username => &self.username,
            SignInField::Password => &self.password,
        }
    }
}

fn contains(rect: &Rectangle, point: Point) -> bool {
    let Point { x, y } = rect.top_left;
    point.x >= x
        && point.y >= y
        && point.x < x + rect.size.width.cast_signed()
        && point.y < y + rect.size.height.cast_signed()
}

/// The sign-in form field at `(x, y)`, for a click.
pub fn sign_in_field_at(screen: Screen, x: u16, y: u16) -> Option<SignInField> {
    let layout = SignInLayout::new(screen);
    let point = Point::new(i32::from(x), i32::from(y));
    [SignInField::Username, SignInField::Password]
        .into_iter()
        .find(|&field| contains(layout.field(field), point))
}

/// The centre of a sign-in form field.
pub fn sign_in_field_center(screen: Screen, field: SignInField) -> (u16, u16) {
    let layout = SignInLayout::new(screen);
    let rect = layout.field(field);
    let x = rect.top_left.x + rect.size.width.cast_signed() / 2;
    let y = rect.top_left.y + rect.size.height.cast_signed() / 2;
    (
        u16::try_from(x.max(0)).unwrap_or(u16::MAX),
        u16::try_from(y.max(0)).unwrap_or(u16::MAX),
    )
}

/// The sign-in form, see [`SignInPrompt`]. It has no animation, unlike the other screens:
/// it is shown before the viewer has signed in, so it is repainted only when it changes.
pub fn render_sign_in(screen: Screen, prompt: &SignInPrompt) -> Result<Vec<u8>, Infallible> {
    let layout = SignInLayout::new(screen);
    let mut fb = Framebuffer::new(u32::from(screen.width), u32::from(screen.height), BG);

    Image::new(logo(), layout.logo).draw(&mut fb)?;

    let text = MonoTextStyle::new(&FONT_10X20, FG);
    Text::with_alignment("Sign in to Warpgate", layout.title, text, Alignment::Center)
        .draw(&mut fb)?;
    Text::with_alignment("Username", layout.username_label, text, Alignment::Left).draw(&mut fb)?;
    Text::with_alignment("Password", layout.password_label, text, Alignment::Left).draw(&mut fb)?;

    let password = "*".repeat(prompt.password_len);
    for (field, value) in [
        (SignInField::Username, prompt.username),
        (SignInField::Password, password.as_str()),
    ] {
        draw_field(&mut fb, layout.field(field), value, prompt.focus == field);
    }

    if let Some(notice) = prompt.notice {
        let (line, color) = match notice {
            SignInNotice::Error(line) => (line, ERROR),
            SignInNotice::Info(line) => (line, FG),
        };
        Text::with_alignment(
            line,
            layout.notice,
            MonoTextStyle::new(&FONT_10X20, color),
            Alignment::Center,
        )
        .draw(&mut fb)?;
    }

    let dim = MonoTextStyle::new(&FONT_10X20, DIM);
    let mut hint = layout.hints;
    for line in SIGN_IN_HINTS {
        Text::with_alignment(line, hint, dim, Alignment::Center).draw(&mut fb)?;
        hint.y += LINE_H;
    }

    Ok(fb.take_pixels())
}

/// A text field holding `value`. The focused field is lit and has the caret; text too long
/// for the field shows its end, where the typing happens.
fn draw_field(fb: &mut Framebuffer, rect: &Rectangle, value: &str, focused: bool) {
    let _ = RoundedRectangle::new(*rect, CornerRadii::new(Size::new_equal(3)))
        .into_styled(PrimitiveStyle::with_fill(if focused { FG } else { DIM }))
        .draw(fb);

    let room = usize::try_from((rect.size.width.cast_signed() - 2 * FIELD_PADDING) / CHAR_W)
        .unwrap_or(0)
        .max(1);
    let count = value.chars().count();
    let visible: String = value.chars().skip(count.saturating_sub(room)).collect();
    let origin = rect.top_left + Point::new(FIELD_PADDING, FIELD_H / 2 + 6);
    let _ = Text::with_alignment(
        &visible,
        origin,
        MonoTextStyle::new(&FONT_10X20, BG),
        Alignment::Left,
    )
    .draw(fb);

    if focused {
        let typed = i32::try_from(count.min(room)).unwrap_or(0);
        let _ = Rectangle::new(
            Point::new(origin.x + typed * CHAR_W + 1, rect.top_left.y + 8),
            Size::new(2, 20),
        )
        .into_styled(PrimitiveStyle::with_fill(BG))
        .draw(fb);
    }
}

struct CharBoxes<'a> {
    text: &'a str,
    slots: usize,
}

/// Vertical gap kept between the logo and the ball once the screen is too short for
/// [`LOGO_Y`], below which the logo is pinned to the top edge.
const LOGO_GAP: i32 = 40;
/// Logo offset from the top on a screen with room to spare.
const LOGO_Y: i32 = 60;

fn render(
    screen: Screen,
    tick: u64,
    text: &str,
    boxes: Option<CharBoxes>,
) -> Result<Vec<u8>, Infallible> {
    let (w, h) = (i32::from(screen.width), i32::from(screen.height));
    let mut fb = Framebuffer::new(u32::from(screen.width), u32::from(screen.height), BG);

    let cx = w / 2;
    let cy = h / 2 - 24;

    let image = logo();
    let x0 = (w - image.size().width.cast_signed()) / 2;
    // Sits at a fixed offset when there's room, and slides up (never off) when there isn't.
    let logo_y = LOGO_Y
        .min(cy - image.size().height.cast_signed() - LOGO_GAP)
        .max(0);
    Image::new(image, Point::new(x0, logo_y)).draw(&mut fb)?;

    bouncy_ball::bouncy_ball(tick, cx, cy)
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(&mut fb)?;

    let style = MonoTextStyle::new(&FONT_10X20, FG);
    let mut y = cy + 88;
    for line in text.split('\n') {
        Text::with_alignment(line, Point::new(cx, y), style, Alignment::Center).draw(&mut fb)?;
        y += 26;
    }

    let style = MonoTextStyle::new(&FONT_10X20, BG);
    if let Some(boxes) = boxes {
        draw_char_boxes(&mut fb, cx, y + 8, boxes.text, boxes.slots, style);
    }

    Ok(fb.take_pixels())
}

mod char_boxes {
    use super::*;

    const OTP_BOX_W: i32 = 30;
    const OTP_BOX_H: i32 = 40;
    const OTP_BOX_GAP: i32 = 8;

    /// Draw a centred row of `slots` rounded boxes, filling each with the matching character of
    /// `text` (left to right); boxes past the end of `text` are left empty.
    pub fn draw_char_boxes(
        fb: &mut Framebuffer,
        cx: i32,
        y: i32,
        text: &str,
        slots: usize,
        style: MonoTextStyle<'_, Rgb888>,
    ) {
        #[allow(clippy::cast_possible_wrap)]
        let slots = slots as i32;
        let total_w = slots * OTP_BOX_W + (slots - 1) * OTP_BOX_GAP;
        let mut x = cx - total_w / 2;
        for i in 0..slots {
            let _ = RoundedRectangle::new(
                Rectangle::new(
                    Point::new(x, y),
                    Size::new(OTP_BOX_W as u32, OTP_BOX_H as u32),
                ),
                CornerRadii::new(Size::new_equal(3)),
            )
            .into_styled(PrimitiveStyle::with_fill(FG))
            .draw(fb);
            if let Some(ch) = text.chars().nth(i as usize) {
                let _ = Text::with_alignment(
                    &ch.to_string(),
                    Point::new(x + OTP_BOX_W / 2 - 1, y + OTP_BOX_H / 2 + 6),
                    style,
                    Alignment::Center,
                )
                .draw(fb);
            }
            x += OTP_BOX_W + OTP_BOX_GAP;
        }
    }
}

#[cfg(test)]
mod sign_in_tests {
    use super::*;

    const SCREENS: [Screen; 3] = [
        Screen {
            width: 1024,
            height: 768,
        },
        Screen {
            width: 1920,
            height: 1080,
        },
        Screen {
            width: 640,
            height: 480,
        },
    ];

    #[test]
    fn a_click_lands_on_the_field_drawn_there() {
        for screen in SCREENS {
            for field in [SignInField::Username, SignInField::Password] {
                let (x, y) = sign_in_field_center(screen, field);
                assert_eq!(sign_in_field_at(screen, x, y), Some(field));
            }
            assert_eq!(sign_in_field_at(screen, 0, 0), None);
        }
    }

    /// A viewer can be as small as the protocol allows, and a password longer than its field.
    #[test]
    fn renders_a_whole_frame_on_any_screen() {
        for screen in [
            Screen {
                width: 200,
                height: 200,
            },
            Screen::default(),
        ] {
            let pixels = render_sign_in(
                screen,
                &SignInPrompt {
                    username: "alice:a-target-name-longer-than-the-username-field-is-wide",
                    password_len: 256,
                    focus: SignInField::Password,
                    notice: Some(SignInNotice::Error("The username or password is incorrect")),
                },
            )
            .unwrap();
            assert_eq!(
                pixels.len(),
                usize::from(screen.width) * usize::from(screen.height) * 3
            );
        }
    }

    #[test]
    fn the_layout_has_room_for_every_hint() {
        assert_eq!(
            SIGN_IN_HINTS.len(),
            usize::try_from(SIGN_IN_HINT_LINES).unwrap()
        );
    }
}
