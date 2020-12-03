import click

from src.util.default_root import DEFAULT_ROOT_PATH

root_path_option = click.option(
    "--root-path",
    "-r",
    type=click.Path(dir_okay=False, resolve_path=True, writable=True),
    default=DEFAULT_ROOT_PATH,
    hidden=False,
    help="Config file root (defaults to %s)." % DEFAULT_ROOT_PATH
)


def default_options():
    def decorator(f):
        # Add default options here (options for every command)
        f = root_path_option(f)
        return f

    return decorator
