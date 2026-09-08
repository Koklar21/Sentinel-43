from pathlib import Path

path = Path("/mnt/data/sentinel43_main_recode.py")
text = path.read_text(encoding="utf-8")

text = text.replace(
'''async def _remove_ws_client(websocket: WebSocket) -> None:
    client: WebSocketClient | None = None
    async with runtime.ws_lock:
        client = runtime.ws_clients.pop(websocket, None)

    if client is not None:
        try:
            runtime.ws_capacity.release()
        except ValueError:
            pass
''',
'''async def _remove_ws_client(websocket: WebSocket) -> None:
    # Connection-capacity ownership belongs to dashboard_websocket().
    # Removing a client from the broadcast registry must not release the
    # semaphore, otherwise writer failure + handler cleanup can double-release.
    async with runtime.ws_lock:
        runtime.ws_clients.pop(websocket, None)
'''
)

text = text.replace(
'''try:
    from core.middleware import FirewallConfig, SentinelFirewall

    app.add_middleware(
        SentinelFirewall,
        config=FirewallConfig.from_env(),
        monitoring_manager=runtime.monitoring_manager,
    )
''',
'''try:
    from core.middleware import FirewallConfig, SentinelFirewall

    class RuntimeMonitoringProxy:
        def __getattr__(self, name: str) -> Any:
            manager = runtime.monitoring_manager
            if manager is None:
                raise RuntimeError("MonitoringManager is not initialized")
            return getattr(manager, name)

    app.add_middleware(
        SentinelFirewall,
        config=FirewallConfig.from_env(),
        monitoring_manager=RuntimeMonitoringProxy(),
    )
'''
)

path.write_text(text, encoding="utf-8")
print("patched", path)
