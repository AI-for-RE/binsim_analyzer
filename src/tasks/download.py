from .tasks_common import Task
from bindiff_types import Library

class DownloadTask(Task[tuple[Library, str]]):

    task_name = 'download'
    needs_temp = True
    needs_ghidra = False

    def do_task(self, task_args: tuple[Library, str]) -> None:

        library, version = task_args

        # Do the download
        library.download(
            download_path=self.temp_dir,
            source_path=self.output_dir,
            version=version,
            log_file=self.log_file
        )