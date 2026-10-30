from __future__ import annotations

import unittest

from cli.platform_d import MAX_PAYLOAD_BYTES, make_payload, parse_payload_sizes, summarize
from scripts.platform_d_probe import parse_ping_output


class PlatformDHelperTests(unittest.TestCase):
    def test_parse_default_payload_sizes(self) -> None:
        self.assertEqual(parse_payload_sizes("1024,102400,10485760"), (1024, 102400, 10485760))

    def test_reject_zero_payload_size(self) -> None:
        with self.assertRaises(Exception):
            parse_payload_sizes("1024,0")

    def test_reject_duplicate_payload_size(self) -> None:
        with self.assertRaises(Exception):
            parse_payload_sizes("1024,1024")

    def test_reject_payload_over_frame_limit(self) -> None:
        with self.assertRaises(Exception):
            parse_payload_sizes(str(MAX_PAYLOAD_BYTES + 1))

    def test_payload_is_deterministic(self) -> None:
        first = make_payload(4096, "D_TEST", "QFF26-PQC-1", 1, 1)
        second = make_payload(4096, "D_TEST", "QFF26-PQC-1", 1, 1)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 4096)

    def test_payload_changes_between_rounds(self) -> None:
        first = make_payload(1024, "D_TEST", "QFF26-PQC-1", 1, 1)
        second = make_payload(1024, "D_TEST", "QFF26-PQC-1", 1, 2)
        self.assertNotEqual(first, second)

    def test_summary_statistics(self) -> None:
        result = summarize([1.0, 2.0, 3.0, 4.0], "ms")
        self.assertEqual(result["n"], 4)
        self.assertEqual(result["min"], 1.0)
        self.assertEqual(result["median"], 2.5)
        self.assertEqual(result["p95"], 3.85)
        self.assertEqual(result["max"], 4.0)

    def test_parse_macos_ping(self) -> None:
        output = (
            "30 packets transmitted, 29 packets received, 3.3% packet loss\n"
            "round-trip min/avg/max/stddev = 1.100/2.200/3.300/0.400 ms\n"
        )
        result = parse_ping_output(output)
        self.assertEqual(result["packets_sent"], 30)
        self.assertEqual(result["packets_received"], 29)
        self.assertAlmostEqual(float(result["packet_loss_pct"]), 3.3)
        self.assertAlmostEqual(float(result["rtt_avg_ms"]), 2.2)

    def test_parse_linux_ping(self) -> None:
        output = (
            "30 packets transmitted, 30 received, 0% packet loss, time 29012ms\n"
            "rtt min/avg/max/mdev = 0.321/1.234/3.456/0.500 ms\n"
        )
        result = parse_ping_output(output)
        self.assertEqual(result["packets_sent"], 30)
        self.assertEqual(result["packets_received"], 30)
        self.assertEqual(result["packet_loss_pct"], 0.0)
        self.assertAlmostEqual(float(result["rtt_max_ms"]), 3.456)

    def test_parse_windows_ping(self) -> None:
        output = (
            "Packets: Sent = 30, Received = 28, Lost = 2 (6% loss),\n"
            "Minimum = 1ms, Maximum = 8ms, Average = 3ms\n"
        )
        result = parse_ping_output(output)
        self.assertEqual(result["packets_sent"], 30)
        self.assertEqual(result["packets_received"], 28)
        self.assertEqual(result["packet_loss_pct"], 6.0)
        self.assertEqual(result["rtt_avg_ms"], 3.0)

    def test_parse_ping_total_loss_without_rtt_summary(self) -> None:
        output = "30 packets transmitted, 0 packets received, 100.0% packet loss\n"
        result = parse_ping_output(output)
        self.assertEqual(result["packets_received"], 0)
        self.assertEqual(result["packet_loss_pct"], 100.0)
        self.assertIsNone(result["rtt_avg_ms"])

    def test_reject_unrecognized_ping_output(self) -> None:
        with self.assertRaises(ValueError):
            parse_ping_output("ping: unknown host")


if __name__ == "__main__":
    unittest.main(verbosity=2)
