//! Clips an operation's own wait to one immutable command deadline.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use crate::error::{Error, ErrorKind};

/// The budget that limits a wait; the command wins an equal-budget tie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// The operation's independently configured budget.
    Operation,
    /// The remaining end-to-end command budget.
    Command,
}

/// A wait clipped without rounding away fractional seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait {
    /// How long the caller may wait.
    pub duration: Duration,
    /// Which timeout contract applies when this wait expires.
    pub limit: Limit,
}

/// Clips `configured` to the remaining command time at explicit `now`.
#[must_use]
pub fn clipped_wait(configured: Duration, deadline: Option<Instant>, now: Instant) -> Wait {
    if let Some(deadline) = deadline {
        let remaining = deadline.saturating_duration_since(now);
        if remaining <= configured {
            return Wait {
                duration: remaining,
                limit: Limit::Command,
            };
        }
    }
    Wait {
        duration: configured,
        limit: Limit::Operation,
    }
}

/// Refuses to start work after an optional command budget has expired.
pub(crate) fn check(deadline: Option<Instant>) -> Result<(), Error> {
    check_at(deadline, Instant::now())
}

fn check_at(deadline: Option<Instant>, now: Instant) -> Result<(), Error> {
    if deadline.is_some_and(|deadline| now >= deadline) {
        Err(timeout())
    } else {
        Ok(())
    }
}

/// Checks before and after completed blocking work without replacing its error.
pub(crate) fn operation<T>(
    deadline: Option<Instant>,
    work: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    operation_with_clock(deadline, &Instant::now, work)
}

fn operation_with_clock<T>(
    deadline: Option<Instant>,
    now: &dyn Fn() -> Instant,
    work: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    check_at(deadline, now())?;
    let value = work()?;
    check_at(deadline, now()).map(|()| value)
}

/// Refuses expired dispatch before even invoking the future's factory.
/// Once started, preserves the operation's delivery and timeout contract.
pub(crate) async fn dispatch<T, F: Future<Output = Result<T, Error>>>(
    deadline: Option<Instant>,
    work: impl FnOnce() -> F,
) -> Result<T, Error> {
    check(deadline)?;
    work().await
}

/// The end-to-end budget error, without server data or credentials.
pub(crate) fn timeout() -> Error {
    Error::new(ErrorKind::RequestTimeout, "the command deadline expired")
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn clipping_preserves_exact_durations_and_identifies_the_limit() {
        let now = Instant::now();
        let short = Duration::from_millis(250);
        let long = Duration::from_secs(3);
        let cases = [
            (long, None, long, Limit::Operation),
            (long, Some(now + short), short, Limit::Command),
            (long, Some(now - short), Duration::ZERO, Limit::Command),
            (short, Some(now + long), short, Limit::Operation),
            (long, Some(now + long), long, Limit::Command),
            (
                Duration::ZERO,
                Some(now + long),
                Duration::ZERO,
                Limit::Operation,
            ),
            (Duration::ZERO, Some(now), Duration::ZERO, Limit::Command),
        ];
        for (configured, deadline, duration, limit) in cases {
            assert_eq!(
                clipped_wait(configured, deadline, now),
                Wait { duration, limit }
            );
        }
    }

    #[test]
    fn only_an_expired_command_prevents_starting_work() {
        assert!(check(None).is_ok());
        assert!(check(Some(Instant::now() + Duration::from_secs(60))).is_ok());
        let expired = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            check(Some(expired)).map_err(|error| error.kind()),
            Err(ErrorKind::RequestTimeout)
        );
    }

    #[test]
    fn blocking_work_does_not_start_after_expiry() {
        let now = Instant::now();
        for (deadline, expected, expected_state) in [
            (Some(now), Err(ErrorKind::RequestTimeout), 7),
            (Some(now + Duration::from_secs(1)), Ok(9), 8),
            (None, Ok(9), 8),
        ] {
            let state = Cell::new(7);
            let result = operation_with_clock(deadline, &|| now, || {
                state.set(8);
                Ok(9)
            });
            assert_eq!(result.map_err(|error| error.kind()), expected);
            assert_eq!(state.get(), expected_state);
        }
    }

    #[test]
    fn completed_work_and_late_completion_keep_their_actual_state() {
        let start = Instant::now();
        for late in [false, true] {
            let now = Cell::new(start);
            let state = Cell::new(7);
            let result =
                operation_with_clock(Some(start + Duration::from_secs(1)), &|| now.get(), || {
                    state.set(8);
                    if late {
                        now.set(start + Duration::from_secs(2));
                    }
                    Ok(9)
                });
            assert_eq!(state.get(), 8);
            let observed = result.map_err(|error| (error.kind(), error.retains_credential_lock()));
            assert_eq!(
                observed,
                if late {
                    Err((ErrorKind::RequestTimeout, false))
                } else {
                    Ok(9)
                }
            );
        }
    }

    #[test]
    fn an_operation_error_survives_expiry_with_its_retention_marker() {
        let start = Instant::now();
        let now = Cell::new(start);
        let error =
            Error::new(ErrorKind::RequestTimeout, "abandoned worker").retaining_credential_lock();
        let result: Result<(), Error> =
            operation_with_clock(Some(start + Duration::from_secs(1)), &|| now.get(), || {
                now.set(start + Duration::from_secs(2));
                Err(error.clone())
            });
        assert_eq!(result, Err(error));
    }

    #[tokio::test]
    async fn expired_dispatch_neither_constructs_nor_polls_work() {
        let expired = Instant::now() - Duration::from_secs(1);
        for (deadline, expected, expected_work) in [
            (Some(expired), Err(ErrorKind::RequestTimeout), false),
            (None, Ok(9), true),
        ] {
            let started = Cell::new(false);
            let polled = Cell::new(false);
            let result = dispatch(deadline, || {
                started.set(true);
                async {
                    polled.set(true);
                    Ok(9)
                }
            })
            .await;
            assert_eq!(result.map_err(|error| error.kind()), expected);
            assert_eq!(started.get(), expected_work);
            assert_eq!(polled.get(), expected_work);
        }
    }

    #[tokio::test]
    async fn dispatched_results_preserve_delivery_errors_and_success() {
        let error = Error::new(ErrorKind::DeliveryUnknown, "may have executed");
        let failed: Result<(), Error> = dispatch(None, || async { Err(error.clone()) }).await;
        assert_eq!(failed, Err(error));
        assert_eq!(dispatch(None, || async { Ok(9) }).await, Ok(9));
    }
}
