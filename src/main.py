from collections.abc import Sequence
import shutil
import os
import argparse
import multiprocessing as mp
from statistics import mean
import yaml
import msgpack

from typing import Any

from bindiff_types import Library, ByteRange

import tasks
from tasks.tasks_common import *

# ORDERED list of all available tasks.
AVAILABLE_TASKS: list[type[Task[Any]]] = [tasks.DownloadTask, tasks.BuildTask, tasks.ExtractTask, tasks.MapTask, tasks.AnalyzeTask]

def execute_task_pool(task: type[Task[Any]], task_pool: Sequence[tuple[Task[Any], Any]], n_procs: int, process_log_dir: str | None) -> None:
    n_tasks = len(task_pool)
    print(f"Stage {task.task_name}: Generated {n_tasks} tasks, running with {n_procs} processes...")
    initializer = None
    if task.needs_ghidra:
        initializer = init_ghidra_worker
    with mp.Pool(processes=n_procs, initializer=initializer, initargs=(None,)) as pool:
        results = pool.starmap(run_task, task_pool)
    failed = [task_pool[i][0].task_id for i in range(len(results)) if results[i] == False]
    print(f"All {task.task_name} tasks complete ({n_tasks - len(failed)}/{n_tasks} succeeded).\nFailed tasks: {failed}")

# Get the analysis priority of a function by name in a function map
# Take into consideration its average size across binaries, and the amount of entries in the byte range list
def get_analysis_priority(function_map: tasks.analyze.FunctionMap, name: str) -> float:
    function_entries = function_map[name]
    # TODO: Factor in number of entries in byte range list?
    average_size = mean([sum([range.size() for range in v[1]]) for v in function_entries])
    return average_size

def main() -> None:

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--modes", required=True, nargs="*", choices=[task.task_name for task in AVAILABLE_TASKS], help="Select which operations to perform.")
    parser.add_argument("--out_dir", type=str, default="out", help="Location for task output files.")
    parser.add_argument("--logs_dir", type=str, default="logs", help="Location for task log files.")
    parser.add_argument("--temp_dir", type=str, default=".tmp", help="Location for task-specific temporary files.")

    parser.add_argument("--config", type=str, default="config.yaml", help="Configuration file to use.")
    parser.add_argument("--overwrite", action="store_true", help="Whether or not to redo previously-completed jobs within a particular operation.")
    parser.add_argument("--no_delete_temp", action="store_true", help="Stops the program from deleting the temporary directory after finishing. Useful for debugging. However, the program will still clear any pre-existing temp directory when starting up.")

    parser.add_argument("--extra_flags", type=str, default="", help="Additional compiler flags to universally add on top of the existing flags.")
    parser.add_argument("--lto", action="store_true", help="Enables the optimization settings that use LTO (link-time optimization).")
    
    parser.add_argument("--n_procs", type=int, default=1, help="Number of processes to spawn to do concurrent builds.")
    parser.add_argument("--batch_size", type=int, default=100, help="Number of functions per analysis batch.")
    parser.add_argument("--n_batches", type=int, default=25, help="Number of analysis batches.")
    args = parser.parse_args()

    out_dir = args.out_dir
    logs_dir = args.logs_dir
    temp_dir = args.temp_dir

    overwrite = args.overwrite
    extra_flags = args.extra_flags
    lto_enabled = args.lto
    delete_temp = not args.no_delete_temp
    n_procs = args.n_procs
    batch_size = args.batch_size
    n_batches = args.n_batches
    modes: list[str] = args.modes
    config_file = args.config

    if n_procs < 1:
        print(f"Invalid number of processes selected ({n_procs}), defaulting to 1 (no concurrency).")
        n_procs = 1

    # Clear log path
    if logs_dir:
        logs_dir = os.path.abspath(logs_dir)
        if os.path.exists(logs_dir):
            if not (os.path.isdir(logs_dir)):
                print("Error: logs_dir must be a directory.")
                exit(1)
            shutil.rmtree(logs_dir)

    # Create temp directory for file operations
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir,exist_ok=True)

    # Load config
    print("Loading config file...")
    with open(config_file, "r") as f:
        _config = yaml.safe_load(f)

    libraries = [Library(**entry) for entry in _config["libraries"]]
    optimizations_dict: dict[str, str] = _config["optimizations"]    
    ghidra_projects_dir = os.path.abspath(os.path.expanduser(_config["ghidra_projects_dir"]))

    download_task_pool = []
    build_task_pool = []
    extract_task_pool = []
    map_task_pool = []

    # Create function pools for build, extract, map
    for library in libraries:
        for version in library.available_versions:
            versioned_library = f"{library.name}-{version}"
            download_task_pool.append((tasks.DownloadTask(versioned_library, out_dir, logs_dir, temp_dir, overwrite, delete_temp), (library, version)))
            for opt in optimizations_dict.items():
                opt_name = opt[0]
                opt_flags = opt[1]
                if "lto" not in opt_name or lto_enabled:
                    task_id = f"{versioned_library}_{opt_name}"
                    cc_flags = f"{opt_flags} {extra_flags}"
                    
                    build_task_pool.append((tasks.BuildTask(task_id, out_dir, logs_dir, temp_dir, overwrite, delete_temp), (library, tasks.DownloadTask.task_directory(out_dir, versioned_library), cc_flags)))
                    extract_task_pool.append((tasks.ExtractTask(task_id, out_dir, logs_dir, temp_dir, overwrite, delete_temp), (ghidra_projects_dir, library, tasks.BuildTask.task_directory(out_dir, task_id))))
        map_task_pool.append((tasks.MapTask(library.name, out_dir, logs_dir, temp_dir, overwrite, delete_temp), (library, tasks.ExtractTask.task_directory(out_dir, ""))))

    # Download
    if tasks.DownloadTask.task_name in modes:
        execute_task_pool(tasks.DownloadTask, download_task_pool, n_procs, None)

    # Build
    if tasks.BuildTask.task_name in modes:
        execute_task_pool(tasks.BuildTask, build_task_pool, n_procs, None)

    # Extract
    if tasks.ExtractTask.task_name in modes:
        execute_task_pool(tasks.ExtractTask, extract_task_pool, n_procs, None)

    # Map
    if tasks.MapTask.task_name in modes:
        execute_task_pool(tasks.MapTask, map_task_pool, n_procs, None)
    
    # Analysis
    if tasks.AnalyzeTask.task_name in modes:
        map_base_dir = tasks.MapTask.task_directory(out_dir, "")
        map_dirs = os.listdir(map_base_dir)
        for library in libraries:
            libname = library.name
            project_base_dir = os.path.join(ghidra_projects_dir, libname)
            if libname in map_dirs and TASK_COMPLETE_SENTINEL in os.listdir(os.path.join(map_base_dir, libname)):
                print(f"Beginning analysis of library {libname}...")
                # Load packed function map into memory
                map_file = os.path.join(map_base_dir, libname, "function_map.msgpack")
                with open(map_file, 'rb') as f:
                    raw_map = msgpack.unpackb(f.read(), raw=False)
                function_map: tasks.analyze.FunctionMap = {
                    name: [(v[0], [ByteRange(r[0], r[1]) for r in v[1]]) for v in variants]
                    for name, variants in raw_map.items()
                }

                # Prioritise analysis for functions which are likely to be complicated
                function_names = sorted(list(function_map.keys()), reverse=True,
                                        key=lambda name: get_analysis_priority(function_map, name))

                # Build analyse task pool, splitting the function map into batches
                library_analysis_pool = []
                for i in range(0, batch_size*n_batches, batch_size):
                    batch_names = function_names[i:i + batch_size]
                    batch = {name: function_map[name] for name in batch_names}
                    batch_index = i // batch_size
                    task_id = f"{libname}_batch_{batch_index}"
                    # Currently everything kinda breaks if overwrite argument is not True, because batch creation may not be the same every time. So we just set overwrite=True.
                    library_analysis_pool.append((tasks.AnalyzeTask(task_id, out_dir, logs_dir, temp_dir, True, delete_temp), (project_base_dir, batch)))

                # Execute analyse task
                execute_task_pool(tasks.AnalyzeTask, library_analysis_pool, n_procs, None)

            else:
                print(f"Mapping task for {libname} is not completed, skipping analysis.")
        

if __name__ == "__main__":
    main()