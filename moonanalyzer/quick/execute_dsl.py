from typing import List, Set, Optional, Deque
import collections
import traceback

import binaryninja
from binaryninja import BinaryView, Function, PluginCommand, BackgroundTask, Settings


from ..defs import LOGGER_NAME
from ..settings import my_settings
from ..dsl import DSLCommand, CommentCommand, FNameCommand, VNameCommand, parse_bndsl


class ExecuteBNDSLTask(BackgroundTask):
    def __init__(self, bv: BinaryView, dsl_script: str):
        super().__init__("Executing BN-DSL...", can_cancel=True)
        self.bv: BinaryView = bv
        self.log = bv.create_logger(LOGGER_NAME)
        self.dsl_script: str = dsl_script

    def run(self):
        # parse the DSL script
        self.log.log_debug(f"DSL script: {self.dsl_script}")
        commands: list[DSLCommand] = parse_bndsl(self.dsl_script)

        self.log.log_debug(f"Parsed commands: {commands}")
