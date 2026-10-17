"""Pure helpers below every other layer: canonical JSON, hashing, errors, paths, settings.

Everything in this package uses the standard library only and starts no process, thread or
signal handler, so the certifier and the evidence readers may import it (specification §2.3).
"""
