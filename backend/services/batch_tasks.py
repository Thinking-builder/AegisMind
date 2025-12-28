from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import List, Optional
from uuid import uuid4

from backend.models.schemas import BatchFileResult, PerformanceMetrics


@dataclass
class BatchTask:
    task_id: str
    total: int
    completed: int = 0
    current: Optional[str] = None
    status: str = "running"
    results: List[BatchFileResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metrics: Optional[PerformanceMetrics] = None
    message: Optional[str] = None


class BatchTaskStore:
    def __init__(self) -> None:
        self._tasks: dict[str, BatchTask] = {}
        self._lock = Lock()

    def create(self, total: int, errors: Optional[List[str]] = None) -> BatchTask:
        task = BatchTask(task_id=str(uuid4()), total=total, errors=errors or [])
        with self._lock:
            self._tasks[task.task_id] = task
        return task

    def get(self, task_id: str) -> BatchTask:
        with self._lock:
            task = self._tasks.get(task_id)
        if not task:
            raise KeyError(task_id)
        return task

    def set_current(self, task_id: str, filename: str) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.current = filename

    def add_result(self, task_id: str, result: BatchFileResult) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.results.append(result)

    def advance(self, task_id: str) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.completed += 1

    def add_error(self, task_id: str, message: str) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.errors.append(message)

    def complete(self, task_id: str, metrics: Optional[PerformanceMetrics]) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.metrics = metrics
                task.status = "completed"

    def fail(self, task_id: str, message: str) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.status = "failed"
                task.message = message


batch_store = BatchTaskStore()
