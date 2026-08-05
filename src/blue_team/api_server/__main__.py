"""CLI entry point for the API server."""

import uvicorn

from blue_team.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "blue_team.api_server.app:create_app",
        factory=True,
        host=settings.api_host,
        port=settings.api_port,
        log_config=None,
    )


if __name__ == "__main__":
    main()
