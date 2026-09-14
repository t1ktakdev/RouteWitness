"""Correctness tests must never reach the external network."""

import socket

import pytest


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def is_loopback(address):
        if isinstance(address, tuple) and address:
            host = address[0]
            return host in {"127.0.0.1", "::1"}
        return False

    def guarded_connect(sock, address):
        if is_loopback(address):
            return original_connect(sock, address)
        raise AssertionError("Correctness tests must use fake network providers")

    def guarded_connect_ex(sock, address):
        if is_loopback(address):
            return original_connect_ex(sock, address)
        raise AssertionError("Correctness tests must use fake network providers")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
