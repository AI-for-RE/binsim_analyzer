import shutil
import os
import traceback
from abc import ABC, abstractmethod
import time

from pyghidra import HeadlessPyGhidraLauncher
from bindiff_types import *
from typing import Any, Generic, TypeVar

T = TypeVar('T')

TASK_COMPLETE_SENTINEL = ".task_complete"

# Defines the result of a completed task
@dataclass
class TaskResult:
    succeeded: bool
    runtime: float # Runtime in seconds

class Task(ABC, Generic[T]):

    task_name: str
    needs_temp: bool
    needs_ghidra: bool

    task_id: str
    output_dir: str
    logs_dir: str
    temp_dir: str
    overwrite: bool
    delete_temp: bool
    log_file: TextIO

    # Returns a subdirectory uniquely qualified by the task name and ID.
    @classmethod
    def task_directory(cls, dir: str, id: str) -> str:
        return os.path.join(dir, cls.task_name, id)

    @abstractmethod
    def do_task(self, task_args: T) -> None:
        ...

    def write_log(self, message: str) -> None:
        self.log_file.write(message+'\n')
 
    def __init__(self, task_id: str, out_dir: str, logs_dir: str, temp_dir: str, overwrite: bool, delete_temp: bool):
        if not self.task_name:
            raise Exception("Task name undefined.")
        self.task_id = task_id
        self.output_dir = os.path.abspath(self.task_directory(out_dir, self.task_id))
        self.logs_dir = os.path.abspath(self.task_directory(logs_dir, ""))
        self.temp_dir = os.path.abspath(self.task_directory(temp_dir, self.task_id))
        self.overwrite = overwrite
        self.delete_temp = delete_temp

def init_ghidra_worker() -> None:
    """Initializes the Ghidra JVM for a worker process. Intended to be used as a
    multiprocessing.Pool initializer so the JVM starts once per worker."""
    import sys
    
    ghidra_launcher = HeadlessPyGhidraLauncher(verbose=False)
    ghidra_launcher.start()

    # Redirect OS-level stdout/stderr (fd 1/2) to /dev/null to avoid
    # JVM native output clogging the console, while keeping Python's sys.stdout/sys.stderr
    # pointing at the original console so print() still works.
    java_log_file = open("/dev/null", "a", buffering=1)
    sys.stdout = os.fdopen(os.dup(1), "w")
    sys.stderr = os.fdopen(os.dup(2), "w")
    os.dup2(java_log_file.fileno(), 1)
    os.dup2(java_log_file.fileno(), 2)

# Common scaffolding for running any task
from typing import Any
def run_task(task: Task[Any], task_args: Any) -> TaskResult:

    pid = os.getpid()

    task_succeeded = True
    task_runtime = 0.0

    # Skip task if it completed successfully on a previous run and overwrite is off
    sentinel_path = os.path.join(task.output_dir, TASK_COMPLETE_SENTINEL)
    do_task = (not os.path.exists(sentinel_path)) or task.overwrite

    if do_task:

        os.makedirs(task.logs_dir, exist_ok=True)
        task.log_file = open(os.path.join(task.logs_dir, f"{task.task_id}.log"), "w", buffering=1)

        print(f"[PID {pid}] Beginning {task.task_name} task '{task.task_id}'.")
        currtime = time.time()

        try:
            
            # Create temp path
            if task.needs_temp:
                if os.path.exists(task.temp_dir):
                    raise Exception(f"Task '{task.task_id}' failed; temporary path {task.temp_dir} already exists.")
                os.makedirs(task.temp_dir, exist_ok=False)
            
            # Create fresh output path
            if os.path.exists(task.output_dir):
                shutil.rmtree(task.output_dir)
            os.makedirs(task.output_dir, exist_ok=True)

            # Call the specific task function
            task.do_task(task_args)

            # Mark task as complete
            open(sentinel_path, "w").close()

            task_runtime = time.time() - currtime

            print(f"[PID {pid}] {task.task_name} task succeeded for '{task.task_id}' ({task_runtime:.3f}s).")

        except Exception:
            task.write_log(f"ERROR: Task failed -- {traceback.format_exc()}")
            task_runtime = time.time() - currtime

            print(f"[PID {pid}] {task.task_name} task failed for '{task.task_id}' ({task_runtime:.3f}s).")
            task_succeeded = False
        finally:
            task.log_file.flush()
            task.log_file.close()
            if task.delete_temp:
                shutil.rmtree(task.temp_dir, ignore_errors=True)
    else:
        print(f"[PID {pid}] {task.task_name} task for '{task.task_id}' already complete and overwrite=False, skipping.")

    return TaskResult(task_succeeded, task_runtime)
