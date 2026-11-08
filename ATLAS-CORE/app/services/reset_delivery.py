"""Pluggable password-reset delivery. The default drops the token (no email infrastructure ships with ATLAS);
administrators can issue a one-time token out-of-band. Implement `deliver` to send email/chat."""
class ResetDelivery:
    def deliver(self, username: str, token: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class NullDelivery(ResetDelivery):
    def deliver(self, username: str, token: str) -> None:
        return None  # intentionally never logs the token


_delivery: ResetDelivery = NullDelivery()


def get_delivery() -> ResetDelivery:
    return _delivery


def set_delivery(d: ResetDelivery) -> None:
    global _delivery
    _delivery = d
