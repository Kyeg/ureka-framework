import legacy.ticket as ticket
import legacy.ticket_old as ticket_old


def generate_old_ticket(holder_id: str) -> ticket_old.Ticket:
    new_ticket = ticket_old.Ticket()

    new_ticket.ticket_type = "TICKET_TYPE"
    new_ticket.holder_id = holder_id

    return new_ticket


def generate_data_class_ticket(holder_id: str) -> ticket.Ticket:
    new_ticket = ticket.Ticket()

    new_ticket.ticket_type = "TICKET_TYPE"
    new_ticket.holder_id = holder_id

    return new_ticket


# Run/Debug experiments in top-level package
if __name__ == "__main__":
    print(generate_old_ticket(holder_id="test"))
    print(generate_data_class_ticket(holder_id="test"))
    pass
