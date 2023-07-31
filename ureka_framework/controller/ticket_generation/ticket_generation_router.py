from ureka_framework.controller.ticket_generation.ticket_generatation_flow import (
    GenerateXXXTicket,
)
from ureka_framework.data_model.ticket import Ticket


# Invoker
class TicketGenerationRouter:
    def __init__(self) -> None:
        self.ticket_types: dict = {}

    # Set Route-Command
    def add_ticket_type(self, ticket_type: str, command: GenerateXXXTicket) -> None:
        self.ticket_types[ticket_type] = command

    # Execute Command
    def generate_xxx_ticket(self, ticket_type: str, *args, **kwargs) -> Ticket:
        if ticket_type in self.ticket_types:
            command = self.ticket_types[ticket_type]
            return command.execute(*args, **kwargs)
        else:
            print(f"Ticket type '{ticket_type}' not found.")
            return None
