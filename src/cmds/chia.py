import sys
import click
import signal

from src.cmds.init import init
from src.errors import _ErrorHandlingGroup
from src import __version__
from src.options import default_options


def exit_on_interrupt(signal, frame):
    """Handle KeyboardInterrupts by just exiting instead of printing out a stack"""
    click.echo(err=True)
    sys.exit(1)


signal.signal(signal.SIGINT, exit_on_interrupt)

_CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 200,
}

_HELP = "Manage chia blockchain infrastructure (%s)." % __version__

_EPILOG = "Try 'chia start node', 'chia netspace -d 48', or 'chia show -s'."


@click.group(cls=_ErrorHandlingGroup, context_settings=_CONTEXT_SETTINGS, help=_HELP, epilog=_EPILOG)
@default_options()
def chia(state):
    pass


# TODO: Uncomment when all command groups imported
chia.add_command(init)
# chia.add_command(keys)
# chia.add_command(show)
# chia.add_command(stop)
# chia.add_command(version)
# chia.add_command(plots)
# chia.add_command(netspace)
# chia.add_command(run_daemon)
# chia.add_command(wallet)
