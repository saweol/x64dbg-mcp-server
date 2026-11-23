import pytest

from tests.fakes.fake_guest import FakeGuest
from tests.fakes.fake_vm import FakeClock, FakeVm


@pytest.fixture
def fake_guest() -> FakeGuest:
    return FakeGuest()


@pytest.fixture
def fake_vm() -> FakeVm:
    return FakeVm()


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()
