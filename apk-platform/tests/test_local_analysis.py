from pathlib import Path
import sys

API_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(API_ROOT))

from apps.api import main


def test_eager_analysis_is_scheduled_in_background(monkeypatch):
    statuses = []
    started_threads = []

    monkeypatch.setattr(main, "_row_or_404", lambda sample_id: (sample_id,))
    monkeypatch.setattr(
        main,
        "update_sample_status",
        lambda sample_id, status: statuses.append((sample_id, status)),
    )
    monkeypatch.setattr(main.celery_app.conf, "task_always_eager", True)
    monkeypatch.setattr(
        main.threading.Thread,
        "start",
        lambda thread: started_threads.append(thread),
    )

    response = main.run_analysis("sample-1")

    assert response["status"] == "queued"
    assert response["task_id"]
    assert statuses == [("sample-1", "queued")]
    assert len(started_threads) == 1
    assert started_threads[0].daemon is True
