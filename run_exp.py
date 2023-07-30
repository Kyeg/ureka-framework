# Run/Debug experiments in top-level package
from exp.thin_router_v2.command import (
    CreateUserCommand,
    DeleteUserCommand,
    UpdateUserCommand,
)
from exp.thin_router_v2.thin_router import ThinRouter


if __name__ == "__main__":
    router = ThinRouter()

    # Map routes to business logic commands
    router.add_route("/create", CreateUserCommand())
    router.add_route("/update", UpdateUserCommand())
    router.add_route("/delete", DeleteUserCommand())

    # Simulate incoming requests
    router.handle_request("/create", "JohnDoe", "john.doe@example.com")
    router.handle_request("/update", user_id=42, new_data={"name": "JaneDoe"})
    router.handle_request("/delete", user_id=42)
    router.handle_request(
        "/unknown_route"
    )  # This will show a message that the route is not found.
