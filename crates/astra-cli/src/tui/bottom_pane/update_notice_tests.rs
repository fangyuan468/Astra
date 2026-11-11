use super::BottomPane;
use crate::tui::{task_status::TaskStatus, testing::render::buffer_to_string};
use ratatui::{buffer::Buffer, layout::Rect};

const NOTICE: &str =
    "Update available (2026.09.28.1-qa) · Exit Astra, then run astra update to upgrade.";

#[test]
fn update_notice_stays_below_composer_and_status_without_consuming_draft() {
    for width in [40, 80, 120] {
        for active in [false, true] {
            let mut pane = BottomPane::new();
            pane.composer.set_text("my unsent draft");
            pane.footer.model = Some("test-model".into());
            if active {
                pane.set_task_status(TaskStatus::TurnRunning {
                    started_at: std::time::Instant::now(),
                });
            }
            let before = pane.desired_height(width);
            pane.update_notice = Some(NOTICE.into());
            let height = pane.desired_height(width);
            assert!(height > before);
            let area = Rect::new(0, 0, width, height);
            let mut buf = Buffer::empty(area);
            pane.render(area, &mut buf);
            let text = buffer_to_string(&buf);
            let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                normalized.contains(NOTICE),
                "{width}, active={active}: {text}"
            );
            assert!(text.find("my unsent draft").unwrap() < text.find("Update available").unwrap());
            assert!(text.find("test-model").unwrap() < text.find("Update available").unwrap());
            assert_eq!(pane.composer.text(), "my unsent draft");
            let (_, cursor_y) = pane.cursor_position(area).unwrap();
            assert!(cursor_y < height - pane.notice_lines(width).len() as u16);

            pane.update_notice = None;
            assert_eq!(pane.desired_height(width), before);
        }
    }
}

#[test]
fn update_notice_small_terminal_safety() {
    let mut pane = BottomPane::new();
    pane.update_notice = Some(NOTICE.into());
    for width in [1, 20, 80] {
        for height in [0, 1, 3] {
            let area = Rect::new(0, 0, width, height);
            pane.render(area, &mut Buffer::empty(area));
        }
    }
}
