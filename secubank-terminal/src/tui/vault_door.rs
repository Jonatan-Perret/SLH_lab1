//! Vault door drawn on a canvas after a vault is opened.
//!
//! Cosmetic component, shown only after the pipeline allowed the vault to be opened.

use std::f64::consts::{PI, TAU};
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::symbols::Marker;
use ratatui::widgets::canvas::{Context, Line, Rectangle};
use ratatui::widgets::{Block, Paragraph, canvas::Canvas};

/// Time between two frames while the door is on screen.
pub const TICK: Duration = Duration::from_millis(33);

/// Wheel angle (radians, clockwise) added by one key press.
const STEP: f64 = PI / 4.0;

/// Wheel angle needed to draw the bolts: one full turn.
const UNLOCK_ANGLE: f64 = TAU;

/// Share of the remaining wheel angle covered at each frame, so the wheel spins smoothly.
const WHEEL_EASING: f64 = 0.35;

/// Time the door takes to swing open.
const SWING_TIME: Duration = Duration::from_millis(1400);

/// Angle of the fully open door. It is past square so the door clears the frame.
const MAX_DOOR_ANGLE: f64 = 105.0 * PI / 180.0;

/// Smallest canvas width (in cells) the door is drawn in. Below it, only a text is shown.
const MIN_WIDTH: u16 = 24;

/// Smallest canvas height (in cells) the door is drawn in. Below it, only a text is shown.
const MIN_HEIGHT: u16 = 10;

/// What the screen does after a key press.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Next {
    /// Keep showing the door.
    Stay,
    /// Leave for the result screen.
    Done,
}

/// The state of the vault door animation.
pub struct VaultDoor {
    /// Wheel angle the user asked for (radians, clockwise).
    target: f64,
    /// Wheel angle on screen, which follows `target`.
    wheel: f64,
    /// When the door started to swing, once the bolts are drawn.
    swing_start: Option<Instant>,
    /// How far the door is open, from 0 (shut) to 1 (open).
    door: f64,
}

impl VaultDoor {
    /// Builds a shut door with the wheel at rest.
    pub fn new() -> VaultDoor {
        VaultDoor {
            target: 0.0,
            wheel: 0.0,
            swing_start: None,
            door: 0.0,
        }
    }

    /// Checks whether the door is fully open.
    pub fn is_open(&self) -> bool {
        self.door >= 1.0
    }

    /// Handles a key: right spins the wheel, left spins it back, and Enter or Esc skips. Once the
    /// door is open, any key goes on.
    ///
    /// * `key`: The pressed key.
    pub fn handle_key(&mut self, key: KeyEvent) -> Next {
        if self.is_open() {
            return Next::Done;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Esc => return Next::Done,
            // The wheel is stuck once the door swings.
            _ if self.swing_start.is_some() => {}
            KeyCode::Right | KeyCode::Char('l' | ' ') => {
                self.target = (self.target + STEP).min(UNLOCK_ANGLE);
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.target = (self.target - STEP).max(0.0);
            }
            _ => {}
        }
        Next::Stay
    }

    /// Moves the animation one frame forward.
    ///
    /// * `now`: The current time.
    pub fn tick(&mut self, now: Instant) {
        self.wheel += (self.target - self.wheel) * WHEEL_EASING;
        if (self.target - self.wheel).abs() < 1e-3 {
            self.wheel = self.target;
        }
        if self.swing_start.is_none() && unlock_progress(self.wheel) >= 1.0 {
            self.swing_start = Some(now);
        }
        if let Some(start) = self.swing_start {
            self.door = swing_progress(now.saturating_duration_since(start));
        }
    }

    /// Returns the help line for this screen.
    pub fn help_text(&self) -> &'static str {
        if self.is_open() {
            "Press any key to continue"
        } else if self.swing_start.is_some() {
            "Enter/Esc: skip"
        } else {
            "Right/l: spin the wheel   Left/h: spin back   Enter/Esc: skip"
        }
    }

    /// Draws the door and a caption under it.
    ///
    /// * `frame`: The frame to draw on.
    /// * `area`: The area of the frame to draw in.
    /// * `message`: The result message, shown as the caption once the door is open.
    pub fn draw(&self, frame: &mut Frame, area: Rect, message: &str) {
        let [art_area, caption_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);
        let caption = if self.is_open() {
            message
        } else if self.swing_start.is_some() {
            "*clunk*"
        } else {
            "The bolts hold. Spin the wheel clockwise."
        };
        frame.render_widget(Paragraph::new(caption).centered(), caption_area);

        let block = Block::bordered().title("Vault");
        let inner = block.inner(art_area);
        if inner.width < MIN_WIDTH || inner.height < MIN_HEIGHT {
            frame.render_widget(
                Paragraph::new("(terminal too small for the door)").block(block),
                art_area,
            );
            return;
        }

        // One braille cell is 2 by 4 dots and about twice as high as wide, so
        // using dots as units keeps circles round.
        let half_w = f64::from(inner.width);
        let half_h = f64::from(inner.height) * 2.0;
        let radius = half_w.min(half_h) * 0.72;
        let canvas = Canvas::default()
            .block(block)
            .marker(Marker::Braille)
            .x_bounds([-half_w, half_w])
            .y_bounds([-half_h, half_h])
            .paint(|ctx| self.paint(ctx, radius));
        frame.render_widget(canvas, art_area);
    }

    /// Paints the whole scene: the loot, the frame, then the door on top.
    ///
    /// * `ctx`: The canvas context.
    /// * `r`: The door radius, in canvas units.
    fn paint(&self, ctx: &mut Context, r: f64) {
        let theta = self.door * MAX_DOOR_ANGLE;
        if self.door > 0.45 {
            paint_loot(ctx, r);
            ctx.layer();
        }
        paint_frame(ctx, r);
        ctx.layer();

        let door = Door {
            hinge: -r,
            theta,
            depth: 5.0 * r,
        };
        let steel = Color::Gray;

        // Rim and inner ring.
        door.polyline(ctx, &circle(0.0, 0.0, r, 64), steel);
        door.polyline(ctx, &circle(0.0, 0.0, r * 0.86, 64), Color::DarkGray);

        // Bolts around the rim, sliding in as the wheel turns.
        let out = 1.0 - unlock_progress(self.wheel);
        let bolt_color = if out > 0.0 {
            Color::LightRed
        } else {
            Color::LightGreen
        };
        for k in 0..8 {
            let a = f64::from(k) * TAU / 8.0 + PI / 8.0;
            let tip = r * (0.95 + 0.22 * out);
            door.bolt(ctx, a, tip - r * 0.3, tip, r * 0.05, bolt_color);
        }

        // Wheel: hub, rim and six spokes with knobs, turning clockwise.
        let wheel_color = Color::White;
        door.polyline(ctx, &circle(0.0, 0.0, r * 0.1, 16), wheel_color);
        door.polyline(ctx, &circle(0.0, 0.0, r * 0.38, 40), wheel_color);
        for k in 0..6 {
            let a = f64::from(k) * TAU / 6.0 - self.wheel;
            let (s, c) = a.sin_cos();
            let end = (c * r * 0.52, s * r * 0.52);
            door.line(ctx, (c * r * 0.1, s * r * 0.1), end, wheel_color);
            door.polyline(ctx, &circle(end.0, end.1, r * 0.06, 10), wheel_color);
        }

        // Hinges on the left edge.
        for y in [r * 0.55, -r * 0.55] {
            door.line(ctx, (-r, y - r * 0.12), (-r, y + r * 0.12), Color::DarkGray);
        }
    }
}

/// Returns how far the bolts are drawn, from 0 (locked) to 1 (free).
///
/// * `wheel`: The wheel angle (radians, clockwise).
fn unlock_progress(wheel: f64) -> f64 {
    (wheel / UNLOCK_ANGLE).clamp(0.0, 1.0)
}

/// Returns how far the door is open, from 0 (shut) to 1 (open). It eases out, so the heavy door
/// slows down at the end.
///
/// * `elapsed`: The time since the door started to swing.
fn swing_progress(elapsed: Duration) -> f64 {
    let t = (elapsed.as_secs_f64() / SWING_TIME.as_secs_f64()).clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// Returns the points of a closed circle: the last point is the first.
///
/// * `cx`: The `x` of the center.
/// * `cy`: The `y` of the center.
/// * `r`: The radius.
/// * `segments`: The number of straight segments.
fn circle(cx: f64, cy: f64, r: f64, segments: u32) -> Vec<(f64, f64)> {
    (0..=segments)
        .map(|i| {
            let a = f64::from(i) * TAU / f64::from(segments);
            (cx + r * a.cos(), cy + r * a.sin())
        })
        .collect()
}

/// The door swinging on a vertical hinge, seen in perspective.
struct Door {
    /// `x` of the hinge, on the left edge of the door.
    hinge: f64,
    /// Swing angle (radians), 0 when the door is shut.
    theta: f64,
    /// Distance from the viewer to the wall, for the perspective.
    depth: f64,
}

impl Door {
    /// Returns where a point of the shut door is on screen once the door swung.
    ///
    /// * `p`: The point on the shut door.
    fn project(&self, p: (f64, f64)) -> (f64, f64) {
        let from_hinge = p.0 - self.hinge;
        let (s, c) = self.theta.sin_cos();
        // The door swings towards the viewer, so its far side looks bigger.
        let toward_viewer = from_hinge * s;
        let scale = self.depth / (self.depth - toward_viewer);
        (self.hinge + from_hinge * c * scale, p.1 * scale)
    }

    /// Draws a line between two points of the door.
    ///
    /// * `ctx`: The canvas context.
    /// * `a`: The start of the line on the shut door.
    /// * `b`: The end of the line on the shut door.
    /// * `color`: The color of the line.
    fn line(&self, ctx: &mut Context, a: (f64, f64), b: (f64, f64), color: Color) {
        let (a, b) = (self.project(a), self.project(b));
        ctx.draw(&Line::new(a.0, a.1, b.0, b.1, color));
    }

    /// Draws a line through a list of points of the door.
    ///
    /// * `ctx`: The canvas context.
    /// * `points`: The points on the shut door, in order.
    /// * `color`: The color of the line.
    fn polyline(&self, ctx: &mut Context, points: &[(f64, f64)], color: Color) {
        for pair in points.windows(2) {
            if let [a, b] = pair {
                self.line(ctx, *a, *b, color);
            }
        }
    }

    /// Draws a bolt: a thin bar from the center outwards.
    ///
    /// * `ctx`: The canvas context.
    /// * `angle`: The direction of the bolt.
    /// * `from`: The distance of its inner end from the center.
    /// * `to`: The distance of its outer end from the center.
    /// * `half_width`: Half of its width.
    /// * `color`: The color of the bolt.
    fn bolt(
        &self,
        ctx: &mut Context,
        angle: f64,
        from: f64,
        to: f64,
        half_width: f64,
        color: Color,
    ) {
        let (s, c) = angle.sin_cos();
        let (nx, ny) = (-s * half_width, c * half_width);
        let corners = [
            (c * from + nx, s * from + ny),
            (c * to + nx, s * to + ny),
            (c * to - nx, s * to - ny),
            (c * from - nx, s * from - ny),
            (c * from + nx, s * from + ny),
        ];
        self.polyline(ctx, &corners, color);
    }
}

/// Draws the wall frame around the door. It does not move.
///
/// * `ctx`: The canvas context.
/// * `r`: The door radius.
fn paint_frame(ctx: &mut Context, r: f64) {
    let f = r * 1.25;
    ctx.draw(&Rectangle {
        x: -f,
        y: -f,
        width: 2.0 * f,
        height: 2.0 * f,
        color: Color::DarkGray,
    });
}

/// Draws what is behind the door: a stack of gold bars.
///
/// * `ctx`: The canvas context.
/// * `r`: The door radius.
fn paint_loot(ctx: &mut Context, r: f64) {
    let (w, h) = (r * 0.5, r * 0.22);
    let gold = Color::Yellow;
    for (row, count) in [(0.0, 3_u32), (1.0, 2), (2.0, 1)] {
        let left = -f64::from(count) * w / 2.0;
        for i in 0..count {
            ctx.draw(&Rectangle {
                x: left + f64::from(i) * w + w * 0.05,
                y: -r * 0.8 + row * h,
                width: w * 0.9,
                height: h * 0.85,
                color: gold,
            });
        }
    }
    ctx.print(
        -r * 0.1,
        -r * 0.05,
        ratatui::text::Line::styled("$$$", Style::new().fg(gold)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyModifiers;

    /// Builds a key press without modifiers.
    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn shut_door_is_not_moved() {
        let door = Door {
            hinge: -10.0,
            theta: 0.0,
            depth: 50.0,
        };
        let p = door.project((3.0, -4.0));
        assert!((p.0 - 3.0).abs() < 1e-9 && (p.1 + 4.0).abs() < 1e-9);
    }

    #[test]
    fn hinge_stays_put() {
        let door = Door {
            hinge: -10.0,
            theta: 1.2,
            depth: 50.0,
        };
        let p = door.project((-10.0, 7.0));
        assert!((p.0 + 10.0).abs() < 1e-9 && (p.1 - 7.0).abs() < 1e-9);
    }

    #[test]
    fn swing_eases_from_shut_to_open() {
        assert_eq!(swing_progress(Duration::ZERO), 0.0);
        assert_eq!(swing_progress(SWING_TIME), 1.0);
        assert_eq!(swing_progress(SWING_TIME * 2), 1.0);
        let half = swing_progress(SWING_TIME / 2);
        assert!(half > 0.5 && half < 1.0);
    }

    #[test]
    fn one_turn_unlocks_and_opens() {
        let mut vault = VaultDoor::new();
        let start = Instant::now();
        for _ in 0..8 {
            assert_eq!(vault.handle_key(press(KeyCode::Right)), Next::Stay);
        }
        for i in 0..60 {
            vault.tick(start + TICK * i);
        }
        assert!(vault.swing_start.is_some());
        vault.tick(start + Duration::from_secs(10));
        assert!(vault.is_open());
        assert_eq!(vault.handle_key(press(KeyCode::Char('x'))), Next::Done);
    }

    #[test]
    fn spinning_back_relocks() {
        let mut vault = VaultDoor::new();
        vault.handle_key(press(KeyCode::Right));
        vault.handle_key(press(KeyCode::Left));
        vault.handle_key(press(KeyCode::Left));
        assert_eq!(vault.target, 0.0);
    }

    #[test]
    fn skip_keys_leave() {
        let mut vault = VaultDoor::new();
        assert_eq!(vault.handle_key(press(KeyCode::Esc)), Next::Done);
        assert_eq!(vault.handle_key(press(KeyCode::Enter)), Next::Done);
    }

    #[test]
    fn draws_at_any_size() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut vault = VaultDoor::new();
        vault.target = UNLOCK_ANGLE;
        let start = Instant::now();
        for (w, h) in [(5, 3), (30, 12), (80, 24), (200, 60)] {
            let Ok(mut terminal) = Terminal::new(TestBackend::new(w, h));
            for i in 0..50 {
                vault.tick(start + TICK * i);
                let drawn = terminal.draw(|f| vault.draw(f, f.area(), "Vault V-001 is open."));
                assert!(drawn.is_ok());
            }
        }
    }
}
