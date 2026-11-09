"""``python -m bunnyhole``: same entry point as the ``bunnyhole`` console script."""

from bunnyhole.cli.main import app


def main() -> None:
    app(prog_name="bunnyhole")


if __name__ == "__main__":
    main()
