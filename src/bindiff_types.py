import subprocess
from dataclasses import dataclass
from typing import TextIO

class Library:
    def __init__(self, name: str, available_versions: list[str], archives: str, build_script: str, download_script: str):
        self.name = name
        self.available_versions = available_versions
        self.archives = archives.split(";") # File locations for all archives we want to analyze, relative to the build directory
        self.build_script = build_script
        self.download_script = download_script

    def build(self, build_path: str, source_path: str, compiler_flags: str, log_file: TextIO | None = None) -> None:

        formatted_cmd = self.build_script.format(
            build_path=build_path,
            source_path=source_path,
            compiler_flags=compiler_flags
        )

        try:
            subprocess.run(formatted_cmd, shell=True, stdout=log_file, stderr=log_file, check=True)
        except subprocess.CalledProcessError as e:
            raise e
        
        if log_file:
            log_file.flush()

    def download(self, download_path: str, source_path: str, version: str, log_file: TextIO | None = None) -> None:

        # Download path is the path to originally download the files into
        # Source path is the final destination path for the files
        formatted_cmd = self.download_script.format(
            download_path=download_path,
            source_path=source_path,
            version=version
        )

        try:
            subprocess.run(formatted_cmd, shell=True, stdout=log_file, stderr=log_file, check=True)
        except subprocess.CalledProcessError as e:
            raise e

        if log_file:
            log_file.flush()

# Defines a qualified function name (object file + function)
@dataclass
class QualifiedName:
    archive_name: str
    object_name: str
    func_name: str

    @staticmethod
    def from_string(s: str) -> QualifiedName:
        archive_name, object_name, func_name = s.split(':', 2)
        return QualifiedName(archive_name, object_name, func_name)

    def __str__(self) -> str:
        return f"{self.archive_name}:{self.object_name}:{self.func_name}"

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other: object) -> bool:
        return str(self) == str(other)

# TODO: Create a dataclass for defining a compilation variant

# Define a range of bytes
@dataclass
class ByteRange:
    begin_addr: int
    end_addr: int
    def size(self) -> int:
        return self.end_addr - self.begin_addr

# Defines a function's relevant metadata within the context of an object file
@dataclass
class FunctionEntry:
    name: str
    entry_point: int # byte offset in the default address space
    byte_ranges: list[ByteRange]

# Defines a pair of functions and their similarity scores (across many possible similarity metrics)
@dataclass
class SimilarityPair:
    v1: str
    v2: str
    sim_dict: dict[str, float]