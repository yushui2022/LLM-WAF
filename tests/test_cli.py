import unittest
from unittest.mock import patch

from app.cli import build_parser, main


class CliTests(unittest.TestCase):
    def test_build_parser_uses_settings_defaults(self):
        parser = build_parser()
        args = parser.parse_args([])

        self.assertEqual(args.host, "0.0.0.0")
        self.assertEqual(args.port, 8080)
        self.assertEqual(args.log_level, "info")
        self.assertEqual(args.workers, 1)
        self.assertFalse(args.reload)

    def test_main_invokes_uvicorn_with_expected_arguments(self):
        with patch("app.cli.uvicorn.run") as run:
            main(["--host", "127.0.0.1", "--port", "9001", "--log-level", "debug", "--reload", "--workers", "2"])

        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual(args[0], "app.main:app")
        self.assertEqual(kwargs["host"], "127.0.0.1")
        self.assertEqual(kwargs["port"], 9001)
        self.assertEqual(kwargs["log_level"], "debug")
        self.assertTrue(kwargs["reload"])
        self.assertEqual(kwargs["workers"], 1)
        self.assertTrue(kwargs["proxy_headers"])


if __name__ == "__main__":
    unittest.main()
