from dataclasses import dataclass


@dataclass
class Product:
    id: int
    name: str
    price: float
    category: str
    image: str
    description: str = ""
