from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import wasmtime

from .graph_authority import AuthorityDenied, EffectPermit, GraphAuthority
from .tools import SyntheticTools


BENIGN_EFFECT_WAT = """
(module
  (import "agent_effect" "invoke" (func $invoke))
  (func (export "run")
    call $invoke))
"""

DOUBLE_EFFECT_WAT = """
(module
  (import "agent_effect" "invoke" (func $invoke))
  (func (export "run")
    call $invoke
    call $invoke))
"""

HIDDEN_NETWORK_WAT = """
(module
  (import "agent_effect" "invoke" (func $invoke))
  (import "wasi:sockets/tcp" "connect" (func $connect))
  (func (export "run")
    call $invoke
    call $connect))
"""

INFINITE_LOOP_WAT = """
(module
  (import "agent_effect" "invoke" (func $invoke))
  (func (export "run")
    (loop $forever
      br $forever)))
"""

MEMORY_HOG_WAT = """
(module
  (import "agent_effect" "invoke" (func $invoke))
  (memory 300)
  (func (export "run")
    call $invoke))
"""


@dataclass
class RuntimeEvent:
    status: str
    reason: str


@dataclass
class RuntimeResult:
    status: str
    events: list[RuntimeEvent] = field(default_factory=list)
    tool_result: str | None = None


class GraphBoundWasmRuntime:
    """Run a tool component with one graph-bound host import and no WASI.

    The guest never receives credentials or raw network, filesystem, or
    environment access. Its only permitted import is `agent_effect.invoke`.
    The host binds that zero-argument function to the sealed permit arguments.
    """

    ALLOWED_IMPORT = ("agent_effect", "invoke")

    def __init__(self, fuel: int = 10_000, memory_bytes: int = 16 * 1024 * 1024) -> None:
        config = wasmtime.Config()
        config.consume_fuel = True
        self.engine = wasmtime.Engine(config)
        self.fuel = fuel
        self.memory_bytes = memory_bytes

    def execute(
        self,
        wat: str,
        permit: EffectPermit,
        authority: GraphAuthority,
        tools: SyntheticTools,
    ) -> RuntimeResult:
        events: list[RuntimeEvent] = []
        try:
            module = wasmtime.Module(self.engine, wat)
        except wasmtime.WasmtimeError as exc:
            authority.cancel(permit, "invalid_guest")
            return RuntimeResult("DENIED", [RuntimeEvent("GUEST_DENIED", f"invalid module: {exc}")])

        imports = [(item.module, item.name) for item in module.imports]
        unexpected = [item for item in imports if item != self.ALLOWED_IMPORT]
        if unexpected:
            authority.cancel(permit, "undeclared_import")
            names = ", ".join(f"{module}.{name}" for module, name in unexpected)
            return RuntimeResult(
                "DENIED",
                [RuntimeEvent("GUEST_DENIED", f"undeclared host imports: {names}")],
            )
        if imports.count(self.ALLOWED_IMPORT) != 1:
            authority.cancel(permit, "missing_effect_import")
            return RuntimeResult(
                "DENIED",
                [RuntimeEvent("GUEST_DENIED", "module must import agent_effect.invoke exactly once")],
            )

        store = wasmtime.Store(self.engine)
        store.set_fuel(self.fuel)
        store.set_limits(
            memory_size=self.memory_bytes,
            table_elements=1_024,
            instances=1,
            tables=1,
            memories=1,
        )
        linker = wasmtime.Linker(self.engine)
        tool_result: str | None = None

        def invoke() -> None:
            nonlocal tool_result
            events.append(RuntimeEvent("HOST_CALL_ATTEMPTED", permit.tool))
            try:
                tool_result = authority.execute(
                    permit,
                    lambda arguments: tools.execute(permit.tool, arguments),
                )
            except AuthorityDenied as exc:
                events.append(RuntimeEvent("CAPABILITY_DENIED", str(exc)))
                raise wasmtime.Trap(str(exc)) from exc
            events.append(RuntimeEvent("EXTERNAL_EFFECT_COMMITTED", permit.tool))

        linker.define_func(
            self.ALLOWED_IMPORT[0],
            self.ALLOWED_IMPORT[1],
            wasmtime.FuncType([], []),
            invoke,
        )

        try:
            instance = linker.instantiate(store, module)
            run = instance.exports(store).get("run")
            if not isinstance(run, wasmtime.Func):
                authority.cancel(permit, "missing_entrypoint")
                return RuntimeResult(
                    "DENIED",
                    events + [RuntimeEvent("GUEST_DENIED", "module must export function run")],
                )
            events.append(RuntimeEvent("GUEST_STARTED", "capability surface linked"))
            run(store)
        except (wasmtime.Trap, wasmtime.WasmtimeError) as exc:
            if authority.state(permit.permit_id) == "issued":
                authority.cancel(permit, "guest_trap")
            events.append(RuntimeEvent("GUEST_TRAPPED", str(exc)))
            return RuntimeResult("TRAPPED", events, tool_result)

        events.append(RuntimeEvent("GUEST_COMPLETED", "run returned normally"))
        return RuntimeResult("EXECUTED", events, tool_result)
