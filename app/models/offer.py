from __future__ import annotations
from datetime import datetime
from sqlalchemy import Integer, DateTime, Numeric, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app import db

class Offer(db.Model):
    __tablename__ = "offers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(40), nullable=False, default="percent")  # percent/fixed
    value: Mapped[float] = mapped_column(Numeric(10,2), nullable=False, default=0)
    starts_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    product = relationship("Product")

    def __repr__(self) -> str:
        return f"<Offer {self.id} product={self.product_id}>"
