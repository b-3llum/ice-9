"""EventBus hooks for automatic entity extraction on phase completion."""

from __future__ import annotations

import threading
from pathlib import Path

from ice_9.core.events import Event, EventType, event_bus
from ice_9.db.store import Store

_registered = False
_lock = threading.Lock()


def register_intel_hooks(db_path: Path) -> None:
    """Register EventBus subscribers for automatic entity extraction.

    Call once during application startup (e.g. from the API server). On each
    PHASE_COMPLETE event, entities are extracted from that phase's task outputs
    in a background thread so the EventBus is never blocked. Idempotent.
    """
    global _registered
    with _lock:
        if _registered:
            return
        _registered = True

    def on_phase_complete(event: Event) -> None:
        if event.type != EventType.PHASE_COMPLETE or not event.campaign_id:
            return
        # A daemon thread with its own Store — SQLite connections are bound to
        # the thread that created them, so we cannot reuse one across threads.
        threading.Thread(
            target=_extract_phase_entities,
            args=(db_path, event.campaign_id, event.phase_id),
            daemon=True,
        ).start()

    event_bus.subscribe(on_phase_complete)


def _extract_phase_entities(
    db_path: Path, campaign_id: str, phase_id: str | None
) -> None:
    """Extract and persist entities from a completed phase's tasks."""
    from ice_9.intel.extractor import EntityExtractor

    store = None
    try:
        store = Store(db_path, check_same_thread=False)
        campaign = store.get_campaign(campaign_id)
        if not campaign:
            return

        extractor = EntityExtractor(store)
        total_entities = 0
        total_rels = 0

        for phase in campaign.phases:
            # Only process the phase that just completed (all phases if unknown).
            if phase_id and phase.id != phase_id:
                continue
            for task in phase.tasks:
                parsed = task.params.get("_parsed") if task.params else None
                if not parsed:
                    continue
                entities, rels = extractor.extract_and_store(
                    task.tool, parsed, task.target, campaign_id
                )
                total_entities += len(entities)
                total_rels += len(rels)

        if total_entities:
            event_bus.emit(Event(
                type=EventType.ENTITY_EXTRACTED,
                campaign_id=campaign_id,
                phase_id=phase_id,
                data={
                    "entities": total_entities,
                    "relationships": total_rels,
                    "trigger": "phase_complete",
                },
            ))
    except Exception:
        pass  # Never crash the emitter on extraction failure
    finally:
        if store is not None:
            store.close()
