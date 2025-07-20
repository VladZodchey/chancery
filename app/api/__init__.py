"""Builds a blueprint for endpoints.

This module provides:
- api_bp: a blueprint to add endpoints to
"""
from flask import Blueprint

api_bp = Blueprint("api", __name__)