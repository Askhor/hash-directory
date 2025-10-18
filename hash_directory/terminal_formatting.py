import logging
import os
import re

_right_padding = 20
color_ctrl_re = re.compile("ℂ([0-9]*)\\.")

log = logging.getLogger("sort-images")


def _trim_to_terminal_width(string: str):
    string = str(string)
    try:
        terminal_width = os.get_terminal_size().columns - _right_padding
    except OSError:
        return string

    if len(string) <= terminal_width:
        return string

    return string[:terminal_width // 2 - 3] + "..." + string[len(string) - terminal_width // 2:]


def color_start(color):
    return f"\x1b[38;5;{color}m"


def color_end():
    return f"\x1b[m"


def parse_color(string: str) -> str:
    """
    Replaces strings of the form ℂ([0-9]*)\\. with a console control code
    that colors the following text (and removes color if the thing in the brackets is empty)"""

    output = ""
    last_match_index = 0

    for m in color_ctrl_re.finditer(string):
        output += string[last_match_index:m.start()]

        if m.group(1) == "":
            output += color_end()
        else:
            output += color_start(m.group(1))

        last_match_index = m.end()

    return output + string[last_match_index:]


def print_temp(string):
    """Print a temporary string to the console"""
    hide_temp()
    print(_trim_to_terminal_width(string), end="", flush=True)


def hide_temp():
    """Remove the current temporary string from the console"""
    print("\x1b[1G\x1b[2K", end="", flush=True)
