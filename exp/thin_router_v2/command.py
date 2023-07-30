# command.py


# Define an interface for the command object
class Command:
    def execute(self, *args, **kwargs):
        pass


class CreateUserCommand(Command):
    def execute(self, username, email):
        # Business logic to create a user goes here
        print(f"Creating user: {username} with email: {email}")


class UpdateUserCommand(Command):
    def execute(self, user_id, new_data):
        # Business logic to update a user goes here
        print(f"Updating user {user_id} with new data: {new_data}")


class DeleteUserCommand(Command):
    def execute(self, user_id):
        # Business logic to delete a user goes here
        print(f"Deleting user with ID: {user_id}")
