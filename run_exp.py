# Run/Debug experiments in top-level package
import json
from typing import Any, Dict


class Person:
    def __init__(self, name: str, age: int):
        self.name = name
        self.age = age


# Custom serialization function for Person objects
def person_encoder(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, Person):
        return {"name": obj.name, "age": obj.age}
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


if __name__ == "__main__":
    person1 = Person("John", 30)
    person2 = Person("Jane", 28)
    persons = {"person1": person1, "person2": person2}

    # Convert dictionary to JSON using custom serialization function
    json_data = json.dumps(persons, default=person_encoder, indent=4)

    print(person_encoder(person1))
    print(person_encoder(person2))
    print(json_data)
