from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
import json
from secrets import token_bytes, token_hex
from threading import RLock
import time
from typing import Any, Callable, TypeVar

from .tools import canonical_tool_arguments


class AuthorityDenied(RuntimeError):
    """The trusted authority boundary denied an effect."""


@dataclass(frozen=True, order=True)
class RelationTuple:
    """A Zanzibar-style object#relation@subject tuple."""

    object: str
    relation: str
    subject: str

    def __str__(self) -> str:
        return f"{self.object}#{self.relation}@{self.subject}"


@dataclass(frozen=True)
class EffectPermit:
    """A signed, task-bound, one-use request to execute one exact effect."""

    permit_id: str
    owner: str
    task_id: str
    agent_id: str
    tool: str
    arguments_json: str
    graph_epoch: int
    issued_at_ns: int
    signature: str

    @property
    def arguments(self) -> dict[str, Any]:
        return json.loads(self.arguments_json)

    def tamper(self, **changes: Any) -> EffectPermit:
        """Return a modified copy for negative tests; its signature will fail."""
        return replace(self, **changes)


T = TypeVar("T")


class TaskPermissionGraph:
    """Small in-memory ReBAC graph for a reproducible local experiment.

    It uses Zanzibar-style relation tuples but does not claim Zanzibar's
    distributed scale or consistency protocol. Each task has a monotonic epoch.
    A mutation to task authority increments that epoch and invalidates permits
    issued against an older view.
    """

    def __init__(self) -> None:
        self._tuples: set[RelationTuple] = set()
        self._epochs: dict[str, int] = {}
        self._lock = RLock()

    @staticmethod
    def _task(task_id: str) -> str:
        return f"task:{task_id}"

    @staticmethod
    def _user(owner: str) -> str:
        return f"user:{owner}"

    @staticmethod
    def _agent(agent_id: str) -> str:
        return f"agent:{agent_id}"

    @staticmethod
    def _target(tool: str, arguments: dict[str, Any]) -> str:
        if tool == "read_ticket":
            return f"ticket:{arguments['ticket_id']}"
        if tool == "send_email":
            return f"recipient:{arguments['to']}"
        raise AuthorityDenied("tool has no graph target mapping")

    def _mutate(self, task_id: str, relation: RelationTuple, add: bool) -> None:
        with self._lock:
            changed = relation not in self._tuples if add else relation in self._tuples
            if not changed:
                return
            if add:
                self._tuples.add(relation)
            else:
                self._tuples.remove(relation)
            self._epochs[task_id] = self._epochs.get(task_id, 0) + 1

    def create_task(self, task_id: str, owner: str, agent_id: str) -> None:
        self._mutate(
            task_id,
            RelationTuple(self._task(task_id), "owner", self._user(owner)),
            True,
        )
        self._mutate(
            task_id,
            RelationTuple(self._task(task_id), "delegate", self._agent(agent_id)),
            True,
        )

    def grant(self, task_id: str, tool: str, arguments: dict[str, Any]) -> None:
        arguments = canonical_tool_arguments(tool, arguments)
        target = self._target(tool, arguments)
        self._mutate(task_id, RelationTuple(target, tool, self._task(task_id)), True)

    def revoke(self, task_id: str, tool: str, arguments: dict[str, Any]) -> None:
        arguments = canonical_tool_arguments(tool, arguments)
        target = self._target(tool, arguments)
        self._mutate(task_id, RelationTuple(target, tool, self._task(task_id)), False)

    def epoch(self, task_id: str) -> int:
        with self._lock:
            return self._epochs.get(task_id, 0)

    def tuples(self) -> tuple[RelationTuple, ...]:
        with self._lock:
            return tuple(sorted(self._tuples))

    def _check_unlocked(
        self,
        owner: str,
        task_id: str,
        agent_id: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, str]:
        task = self._task(task_id)
        required = (
            RelationTuple(task, "owner", self._user(owner)),
            RelationTuple(task, "delegate", self._agent(agent_id)),
            RelationTuple(self._target(tool, arguments), tool, task),
        )
        missing = [str(item) for item in required if item not in self._tuples]
        if missing:
            return False, f"missing permission relation: {missing[0]}"
        return True, "allowed by current task relationship graph"

    def check(
        self,
        owner: str,
        task_id: str,
        agent_id: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, str, int]:
        with self._lock:
            allowed, reason = self._check_unlocked(owner, task_id, agent_id, tool, arguments)
            return allowed, reason, self._epochs.get(task_id, 0)

    def run_if_current(
        self,
        owner: str,
        task_id: str,
        agent_id: str,
        tool: str,
        arguments: dict[str, Any],
        expected_epoch: int,
        effect: Callable[[], T],
    ) -> T:
        """Linearize the graph recheck and the synthetic effect for this prototype."""
        with self._lock:
            current_epoch = self._epochs.get(task_id, 0)
            if current_epoch != expected_epoch:
                raise AuthorityDenied(
                    f"stale task authority: permit epoch {expected_epoch}, current epoch {current_epoch}"
                )
            allowed, reason = self._check_unlocked(owner, task_id, agent_id, tool, arguments)
            if not allowed:
                raise AuthorityDenied(reason)
            return effect()


class GraphAuthority:
    """Issue and consume signed, one-use permits backed by a relationship graph."""

    def __init__(
        self,
        graph: TaskPermissionGraph,
        signing_key: bytes | None = None,
        max_calls: dict[str, int] | None = None,
    ) -> None:
        self.graph = graph
        self._signing_key = signing_key or token_bytes(32)
        self._max_calls = max_calls or {"read_ticket": 1, "send_email": 1}
        self._states: dict[str, str] = {}
        self._reserved: dict[tuple[str, str], int] = {}
        self._consumed: dict[tuple[str, str], int] = {}
        self._lock = RLock()

    @staticmethod
    def _arguments_json(tool: str, arguments: dict[str, Any]) -> str:
        sealed = canonical_tool_arguments(tool, arguments)
        return json.dumps(sealed, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _payload(permit: EffectPermit) -> bytes:
        values = {
            "permit_id": permit.permit_id,
            "owner": permit.owner,
            "task_id": permit.task_id,
            "agent_id": permit.agent_id,
            "tool": permit.tool,
            "arguments_json": permit.arguments_json,
            "graph_epoch": permit.graph_epoch,
            "issued_at_ns": permit.issued_at_ns,
        }
        return json.dumps(values, sort_keys=True, separators=(",", ":")).encode()

    def _signature(self, permit: EffectPermit) -> str:
        return hmac.new(self._signing_key, self._payload(permit), hashlib.sha256).hexdigest()

    def _valid_signature(self, permit: EffectPermit) -> bool:
        return hmac.compare_digest(self._signature(permit), permit.signature)

    def issue(
        self,
        owner: str,
        task_id: str,
        agent_id: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> EffectPermit:
        arguments_json = self._arguments_json(tool, arguments)
        sealed_arguments = json.loads(arguments_json)
        allowed, reason, epoch = self.graph.check(owner, task_id, agent_id, tool, sealed_arguments)
        if not allowed:
            raise AuthorityDenied(reason)

        key = (task_id, tool)
        with self._lock:
            limit = self._max_calls.get(tool, 0)
            used = self._reserved.get(key, 0) + self._consumed.get(key, 0)
            if used >= limit:
                raise AuthorityDenied(f"{tool} task budget exceeded")
            unsigned = EffectPermit(
                permit_id=token_hex(16),
                owner=owner,
                task_id=task_id,
                agent_id=agent_id,
                tool=tool,
                arguments_json=arguments_json,
                graph_epoch=epoch,
                issued_at_ns=time.time_ns(),
                signature="",
            )
            permit = replace(unsigned, signature=self._signature(unsigned))
            self._states[permit.permit_id] = "issued"
            self._reserved[key] = self._reserved.get(key, 0) + 1
            return permit

    def cancel(self, permit: EffectPermit, reason: str = "cancelled") -> None:
        with self._lock:
            if not self._valid_signature(permit):
                raise AuthorityDenied("invalid permit signature")
            if self._states.get(permit.permit_id) != "issued":
                return
            key = (permit.task_id, permit.tool)
            self._states[permit.permit_id] = reason
            self._reserved[key] -= 1

    def execute(self, permit: EffectPermit, effect: Callable[[dict[str, Any]], T]) -> T:
        """Verify, consume, and run one effect at the current graph epoch.

        The permit is consumed before the effect starts. A failed or lost effect
        is therefore not retried with the same permit. This gives at-most-once
        execution attempts, not a distributed exactly-once guarantee.
        """
        with self._lock:
            if not self._valid_signature(permit):
                raise AuthorityDenied("invalid permit signature")
            state = self._states.get(permit.permit_id)
            if state != "issued":
                raise AuthorityDenied(f"permit is not usable: {state or 'unknown'}")
            arguments = permit.arguments
            key = (permit.task_id, permit.tool)
            committed = False

            def commit() -> T:
                nonlocal committed
                self._states[permit.permit_id] = "consumed"
                self._reserved[key] -= 1
                self._consumed[key] = self._consumed.get(key, 0) + 1
                committed = True
                return effect(arguments)

            try:
                return self.graph.run_if_current(
                    permit.owner,
                    permit.task_id,
                    permit.agent_id,
                    permit.tool,
                    arguments,
                    permit.graph_epoch,
                    commit,
                )
            except AuthorityDenied:
                if not committed:
                    self._states[permit.permit_id] = "denied"
                    self._reserved[key] -= 1
                raise

    def state(self, permit_id: str) -> str | None:
        with self._lock:
            return self._states.get(permit_id)

    def usage(self, task_id: str, tool: str) -> dict[str, int]:
        key = (task_id, tool)
        with self._lock:
            return {
                "reserved": self._reserved.get(key, 0),
                "consumed": self._consumed.get(key, 0),
                "limit": self._max_calls.get(tool, 0),
            }
