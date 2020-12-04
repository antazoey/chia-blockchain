import click

from src.util.default_root import DEFAULT_ROOT_PATH


class CliState:
    def __init__(self):
        self._root_path = None

    @property
    def root_path(self):
        return self._root_path

    @root_path.setter
    def root_path(self, value):
        if value and isinstance(value, str):
            self._root_path = value.lower()


def _set_root_path(ctx, chain):
    if chain and ctx.obj:
        ctx.obj.chain = chain


root_path_option = click.option(
    "--root-path",
    "-r",
    type=click.Path(dir_okay=False, resolve_path=True, writable=True),
    default=DEFAULT_ROOT_PATH,
    expose_value=False,
    hidden=False,
    callback=lambda ctx, param, value: _set_root_path(ctx, value),
    help="Config file root (defaults to %s)." % DEFAULT_ROOT_PATH
)


pass_state = click.make_pass_decorator(CliState, ensure=True)


def default_options():
    def decorator(f):
        # Add default options here (options for every command)
        f = root_path_option(f)
        f = pass_state(f)
        return f

    return decorator
