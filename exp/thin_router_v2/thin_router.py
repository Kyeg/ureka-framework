# thin_router.py


class ThinRouter:
    def __init__(self):
        self.routes = {}

    def add_route(self, route, command):
        self.routes[route] = command

    def handle_request(self, route, *args, **kwargs):
        if route in self.routes:
            command = self.routes[route]
            command.execute(*args, **kwargs)
        else:
            print(f"Route '{route}' not found.")
