"""Objective of the investigation."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Objective:
    """The goal of the investigation, provided at runtime."""
    description: str
