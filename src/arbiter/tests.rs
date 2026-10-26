extern crate std;

use self::std::{cell::RefCell, rc::Rc, vec::Vec};
use super::*;
use core::{cell::Cell, convert::Infallible};
use embedded_time::{fraction::Fraction, Instant};

#[derive(Default)]
struct TestClock(Cell<u32>);
impl embedded_time::Clock for TestClock {
    type T = u32;
    const SCALING_FACTOR: Fraction = Fraction::new(1, 1_000_000);
    fn try_now(&self) -> Result<Instant<Self>, embedded_time::clock::Error> {
        let now = self.0.get();
        self.0.set(now + 100);
        Ok(Instant::new(now))
    }
}

struct Module<'a> {
    clock: &'a TestClock,
    delay_us: u32,
    command: Vec<u8>,
    response: Option<(&'static [u8], usize, u32)>,
}
#[derive(Clone)]
struct Pin<'a>(Rc<RefCell<Module<'a>>>);
impl OutputPin for Pin<'_> {
    type Error = Infallible;
    fn set_low(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn set_high(&mut self) -> Result<(), Self::Error> {
        let mut m = self.0.borrow_mut();
        if !m.command.is_empty() {
            let joining = m.command.starts_with(b"C0\r");
            let delayed = joining || m.command.starts_with(b"D0=");
            let reply: &'static [u8] = if joining {
                b"\r\n[JOIN   ] test,192.168.1.95,0,0\r\nOK\r\n> "
            } else {
                b"\r\nOK\r\n> "
            };
            let ready_at = m.clock.0.get() + if delayed { m.delay_us } else { 0 };
            m.response = Some((reply, 0, ready_at));
            m.command.clear();
        } else if m.response.is_some() {
            m.response = None;
        }
        Ok(())
    }
}
impl InputPin for Pin<'_> {
    type Error = Infallible;
    fn is_high(&self) -> Result<bool, Self::Error> {
        let m = self.0.borrow();
        Ok(match m.response {
            Some((reply, pos, ready_at)) => m.clock.0.get() >= ready_at && pos < reply.len(),
            None => true,
        })
    }
    fn is_low(&self) -> Result<bool, Self::Error> {
        self.is_high().map(|v| !v)
    }
}
impl Transfer<u8> for Pin<'_> {
    type Error = Infallible;
    fn transfer<'w>(&mut self, words: &'w mut [u8]) -> Result<&'w [u8], Self::Error> {
        let mut m = self.0.borrow_mut();
        if let Some((reply, pos, ready_at)) = m.response {
            words[1] = reply.get(pos).copied().unwrap_or(0x15);
            words[0] = reply.get(pos + 1).copied().unwrap_or(0x15);
            m.response = Some((reply, pos + 2, ready_at));
        } else {
            m.command.extend_from_slice(&[words[1], words[0]]);
        }
        Ok(words)
    }
}

fn arbiter(
    clock: &TestClock,
    delay_us: u32,
) -> Arbiter<'_, Pin<'_>, Pin<'_>, Pin<'_>, Pin<'_>, Pin<'_>, TestClock> {
    let pin = Pin(Rc::new(RefCell::new(Module {
        clock,
        delay_us,
        command: Vec::new(),
        response: None,
    })));
    let mut arbiter = Arbiter::new(
        pin.clone(),
        pin.clone(),
        pin.clone(),
        pin.clone(),
        pin,
        clock,
    );
    arbiter.state = DriverState::Ready;
    arbiter
}

#[test]
fn join_accepts_a_response_after_six_seconds() {
    let clock = TestClock::default();
    let mut a = arbiter(&clock, 6_000_000);
    assert!(a
        .join(&JoinInfo::Wep {
            ssid: "test",
            password: "password"
        })
        .is_ok());
    assert!(a.ip == Some([192, 168, 1, 95]));
    assert_eq!(a.ready_timeouts, 0);
    assert!(clock.0.get() >= 6_000_000);
}

#[test]
fn join_still_times_out_after_ten_seconds() {
    let clock = TestClock::default();
    let mut a = arbiter(&clock, 11_000_000);
    assert!(a
        .join(&JoinInfo::Wep {
            ssid: "test",
            password: "password"
        })
        .is_err());
    assert_eq!(a.ready_timeouts, 1);
    assert!((10_000_000..10_100_000).contains(&clock.0.get()));
}

#[test]
fn ordinary_command_keeps_five_second_response_timeout() {
    let clock = TestClock::default();
    let mut a = arbiter(&clock, 6_000_000);
    assert!(a.send(b"D0=example.com\r", &mut [0; 64]).is_err());
    assert_eq!(a.ready_timeouts, 1);
    assert!((5_000_000..5_100_000).contains(&clock.0.get()));
}
