# ============================================================

# API Factory + FastAPI App

# ============================================================

class AnalyzeRequest(BaseModel):
event: dict[str, Any] = Field(default_factory=dict)

NODE_ID = os.getenv("S43_WATCHTOWER_NODE_ID", "sentinel43-watchtower")
CONFIG = WatchtowerConfig.default_sentinel_octagon(NODE_ID)
NODE = WatchtowerNode(CONFIG)
NODE.start()

def create_api_app(node: WatchtowerNode) -> FastAPI:
if not isinstance(node, WatchtowerNode):
raise TypeError(f"node must be WatchtowerNode, got {type(node).**name**}")

```
api = FastAPI(
    title="Sentinel-43 Watchtower",
    version="0.1.0",
    description="Sentinel-43 monitoring and alert analysis node.",
)

@api.get("/health")
def health_check() -> dict[str, Any]:
    return {
        "status": "ok",
        "node_state": node.state.value,
        "node_id": node.config.node_id,
    }

@api.get("/status")
def node_status() -> dict[str, Any]:
    return node.get_status()

@api.post("/analyze")
def analyze_event(payload: AnalyzeRequest) -> dict[str, Any]:
    try:
        alerts = node.scan_event(payload.event)
        return {
            "alerts": alerts,
            "alert_count": len(alerts),
        }
    except Exception as exc:
        logger.exception("Analyze failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@api.post("/state/{state_name}")
def change_state(state_name: str) -> dict[str, Any]:
    try:
        state = WatchtowerState[state_name.upper()]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid state: {state_name}") from exc

    node.set_state(state)
    return {
        "node_id": node.config.node_id,
        "state": node.state.value,
    }

return api
```

app = create_api_app(NODE)

def main() -> None:
uvicorn.run(
"core.monitoring.watchtower:app",
host=CONFIG.host,
port=CONFIG.port,
reload=False,
log_level=os.getenv("S43_LOG_LEVEL", "info").lower(),
)

if **name** == "**main**":
main()
