"""EventBus hooks for automatic entity extraction on phase/task completion."""

from __future__ import annotations

import threading

from ice_9.core.events import Event, EventType, event_bus
from ice_9.db.store import Store

_registered = False
_lock = threading.Lock()


def register_intel_hooks(store: Store) -> None:
    """Register EventBus subscribers for automatic entity extraction.

    Should be called once during application startup. Hooks into
    PHASE_COMPLETE and TOOL_COMPLETE events to extract entities
    from new tool results.
    """
    global _registered
    with _lock:
        if _registered:
            return
        _registered = True

    def on_phase_complete(event: Event) -> None:
        """Extract entities when a phase completes."""
        if event.type != EventType.PHASE_COMPLETE:
            return

        campaign_id = event.campaign_id
        if not campaign_id:
            return

        # Run extraction in a background thread to avoid blocking the EventBus
        thread = threading.Thread(
            target=_extract_phase_entities,
            args=(store, campaign_id),
            daemon=True,
        )
        thread.start()

    event_bus.subscribe(on_phase_complete)


def _extract_phase_entities(store: Store, campaign_id: str) -> None:
    """Background extraction of entities from campaign task outputs."""
    from ice_9.intel.extractor import EntityExtractor

    try:
        campaign = store.get_campaign(campaign_id)
        if not campaign:
            return

        extractor = EntityExtractor(store)
        total_entities = 0
        total_rels = 0

        for phase in campaign.phases:
            for task in phase.tasks:
                if task.output:
                    parsed = task.params.get("_parsed", {})
                    entities, rels = extractor.extract_and_store(
                        task.tool, parsed, task.target, campaign_id
                    )
                    total_entities += len(entities)
                    total_rels += len(rels)

        if total_entities > 0:
            event_bus.emit(Event(
                type=EventType.ENTITY_EXTRACTED,
                campaign_id=campaign_id,
                data={
                    "entities": total_entities,
                    "relationships": total_rels,
                    "trigger": "phase_complete",
                },
            ))
    except Exception:
        pass  # Don't crash the main process on extraction failure
