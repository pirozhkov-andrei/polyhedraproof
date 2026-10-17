"""Immutable contract values, enums and their strict validators (specification §3-§4).

``contracts`` depends only on the standard library and pure ``cubeproof.base`` helpers. It
contains values and validation, never process execution. Readers here are context-free:
they raise :class:`~cubeproof.base.errors.ContractError` named by the requirement violated
(``schema`` with the JSON location for schema-level violations), and the caller converts it
to an input or integrity error for its context.
"""
