import shutil
from .tasks_common import Task
from bindiff_types import Library

class BuildTask(Task[tuple[Library, str, str]]):

    task_name = 'build'
    needs_temp = True

    def do_task(self, task_args: tuple[Library, str, str]) -> None:

        library, source_dir, cc_flags = task_args

        self.write_log(f"Copying source files from {source_dir} into temp directory {self.temp_dir}...")
        shutil.copytree(source_dir, self.temp_dir, dirs_exist_ok=True)

        # Do the build
        library.build(
            build_path=self.output_dir,
            source_path=self.temp_dir,
            compiler_flags=cc_flags,
            log_file=self.log_file
        )