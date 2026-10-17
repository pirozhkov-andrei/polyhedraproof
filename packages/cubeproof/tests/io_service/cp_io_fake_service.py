"""A misbehaving I/O service for the client tests: ``python3 cp_io_fake_service.py MODE``.

It sends a hello, reads job frames and answers each one wrongly according to MODE:
``swap-job`` (the ID of another job), ``swap-attempt`` (another attempt ID), ``wrong-op``,
``duplicate`` (the same result twice), ``garbage`` (not a frame), ``seq-gap`` (an append
result that skips a sequence number), ``wrong-artifact`` (a publication of other bytes),
``no-hello`` (a result first) or ``exit`` (dies after reading the first job). Mode
``fatal`` answers correctly with a fatal failure (as after a failed fsync). ``MODE+valid``
sends the wrong answer of MODE immediately followed, in the same write, by the correct
result of the same job (a client must not deliver anything after the bad frame).
"""

from __future__ import annotations

import os
import sys
import time

from cubeproof.contracts.io import (
    AppendValue,
    Failure,
    HashValue,
    Hello,
    Job,
    Op,
    PublishRequest,
    PublishValue,
    RemoveValue,
    Result,
    decode_frame,
    encode_frame,
)
from cubeproof.contracts.values import Artifact

OTHER_ATTEMPT = "f" * 32
VALID_AFTER = "+valid"


def send(data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(1, view) :]


def answer(mode: str, job: Job) -> list[bytes]:
    request = job.request
    if isinstance(request, PublishRequest):
        art = request.artifact
        if mode == "wrong-artifact":
            art = Artifact(art.path, "0" * 64, art.bytes)
        outcome: object = PublishValue(art, reused=False)
    elif job.op is Op.APPEND:
        outcome = AppendValue(100 if mode == "seq-gap" else 1, "a" * 64)
    else:
        outcome = HashValue(0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    job_id, op, attempt = job.job_id, job.op, job.attempt_id
    if mode == "fatal":  # a well-formed fatal failure (e.g. a failed fsync)
        outcome = Failure("tool", "io.fsync", "injected", True)
    if mode == "swap-job":
        job_id += 1000
    elif mode == "swap-attempt":
        attempt = OTHER_ATTEMPT
    elif mode == "wrong-op":  # a well-formed remove result for a hash job
        op, outcome = Op.REMOVE, RemoveValue(())
    result = Result(job_id, op, attempt, outcome)  # type: ignore[arg-type]
    frame = encode_frame(result.to_json())
    if mode == "duplicate":
        return [frame, frame]
    if mode == "garbage":
        return [b"this is not a frame\n"]
    return [frame]


def main() -> int:
    mode = sys.argv[1]
    if mode != "no-hello":
        send(encode_frame(Hello(os.getpid(), 0, "a" * 64).to_json()))
    buffer = b""
    while True:
        data = os.read(0, 1 << 16)
        if not data:
            return 0
        buffer += data
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            job = Job.from_json(decode_frame(line))
            if mode == "exit":
                return 7
            if mode.endswith(VALID_AFTER):
                # One write (well below PIPE_BUF): the client reads both frames at once.
                frames = answer(mode[: -len(VALID_AFTER)], job) + answer("valid", job)
                send(b"".join(frames))
            else:
                for frame in answer(mode, job):
                    send(frame)
            if mode != "fatal":
                # Ignore the closed input from now on: only a kill ends this process, so
                # the tests can see that the client kills a misbehaving service.
                time.sleep(600)
                return 0


if __name__ == "__main__":
    raise SystemExit(main())
