from ureka_framework.controller.ticket_generator import TicketGenerator

# Run/Debug experiments in top-level package
if __name__ == "__main__":
    f = TicketGenerator.generate_ticket("initialization")
    print(f(holder_id="123"))

    print(TicketGenerator.generate_ticket("initialization")(holder_id="123"))
