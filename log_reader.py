# log_reader.py
import time

def read_log_file(file_path, stop_flag):
    """
    Continuously read log file (including existing lines first),
    then tail for new lines in real time.
    """
    with open(file_path, "r") as file:
        # Read all existing lines once
        for line in file:
            if stop_flag[0]:
                return
            yield line

        # Then tail new lines
        while not stop_flag[0]:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line
